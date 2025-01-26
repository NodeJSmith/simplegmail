"""
File: gmail.py
--------------
Home to the main Gmail service object. Currently supports sending mail (with
attachments) and retrieving mail with the full suite of Gmail search options.

"""

import base64
import contextlib
import html
import logging
import mimetypes
import os
import re
import typing
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import ClassVar, Literal, Optional, Union

import dateutil.parser as parser
import httpx
from bs4 import BeautifulSoup
from googleapiclient.discovery import build
from httplib2 import Http
from oauth2client import client, file, tools
from tenacity import after_log, before_log, before_sleep_log, retry, stop_after_attempt, wait_exponential
from typing_extensions import TypedDict

from simplegmail import label
from simplegmail.attachment import Attachment
from simplegmail.label import Label
from simplegmail.message import Message

if typing.TYPE_CHECKING:
    from googleapiclient._apis.gmail.v1 import GmailResource  # type: ignore


LOG_LEVEL = os.getenv("SIMPLEGMAIL_LOG_LEVEL", "INFO")

LOG_FMT = "{asctime} - {module}.{funcName}:{lineno} - {levelname} - {message}"
DATE_FMT = "%Y-%m-%d %H:%M:%S%z"

LOGGER = logging.getLogger("simplegmail")

LOGGER.setLevel(LOG_LEVEL)

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(fmt=LOG_FMT, datefmt=DATE_FMT, style="{"))

LOGGER.addHandler(handler)

GET_MSG_URL_TEMPLATE = (
    "https://gmail.googleapis.com/gmail/v1/users/{user_id}/messages/{message_id}?format={message_format}&alt=json"
)
MODIFY_MSG_URL_TEMPLATE = "https://gmail.googleapis.com/gmail/v1/users/{user_id}/messages/{message_id}/modify"


ATTACHMENT_FORMAT = Literal["reference", "download", "ignore"]
MESSAGE_FORMAT = Literal["minimal", "full", "metadata"]


CLIENT_SECRET_FILE_NOT_FOUND_MSG = (
    "Your 'client_secret.json' file is nonexistent. Make sure "
    "the file is in the root directory of your application. If "
    "you don't have a client secrets file, go to https://"
    "developers.google.com/gmail/api/quickstart/python, and "
    "follow the instructions listed there."
)


class MessageRef(TypedDict):
    id: str
    threadId: str


class Gmail:
    """
    The Gmail class which serves as the entrypoint for the Gmail service API.

    Args:
        client_secret_file: The path of the user's client secret file.
        creds_file: The path of the auth credentials file (created on first
            call).
        access_type: Whether to request a refresh token for usage without a
            user necessarily present. Either 'online' or 'offline'.

    Attributes:
        client_secret_file (str): The name of the user's client secret file.
        service (GmailResource): The Gmail service object.

    """

    # Allow Gmail to read and write emails, and access settings like aliases.
    _SCOPES: ClassVar[list[str]] = [
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.settings.basic",
    ]

    # If you don't have a client secret file, follow the instructions at:
    # https://developers.google.com/gmail/api/quickstart/python
    # Make sure the client secret file is in the root directory of your app.

    def __init__(
        self,
        client_secret_file: str = "client_secret.json",
        creds_file: str = "gmail_token.json",
        access_type: str = "offline",
        noauth_local_webserver: bool = False,
        _creds: Optional[client.OAuth2Credentials] = None,
    ) -> None:
        self.client_secret_file = client_secret_file
        self.creds_file = creds_file

        # The file gmail_token.json stores the user's access and refresh
        # tokens, and is created automatically when the authorization flow
        # completes for the first time.
        if _creds:
            self.creds = _creds
        else:
            store = file.Storage(self.creds_file)
            self.creds = store.get()

        if not self.creds or self.creds.invalid:
            if not Path(self.client_secret_file).exists():
                raise FileNotFoundError(CLIENT_SECRET_FILE_NOT_FOUND_MSG)

            flow = client.flow_from_clientsecrets(self.client_secret_file, self._SCOPES)

            flow.params["access_type"] = access_type
            flow.params["prompt"] = "consent"

            args = []
            if noauth_local_webserver:
                args.append("--noauth_local_webserver")

            flags = tools.argparser.parse_args(args)
            self.creds = tools.run_flow(flow, store, flags)

        self._service: GmailResource = build("gmail", "v1", http=self.creds.authorize(Http()), cache_discovery=False)

        self.labels = {x.id: x for x in self.list_labels(user_id="me")}

    @property
    def service(self) -> "GmailResource":
        # Since the token is only used through calls to the service object,
        # this ensure that the token is always refreshed before use.
        if self.creds.access_token_expired:
            self.creds.refresh(Http())

        return self._service

    @property
    def _messages(self) -> "GmailResource.UsersResource.MessagesResource":
        return self.service.users().messages()

    def reload_labels(self) -> None:
        """
        Reloads the labels for the Gmail account.

        """

        self.labels = {x.id: x for x in self.list_labels(user_id="me")}

    def send_message(
        self,
        sender: str,
        to: str,
        subject: str = "",
        msg_html: Optional[str] = None,
        msg_plain: Optional[str] = None,
        cc: Optional[list[str]] = None,
        bcc: Optional[list[str]] = None,
        attachments: Optional[list[str]] = None,
        signature: bool = False,
        user_id: str = "me",
    ) -> Message:
        """
        Sends an email.

        Args:
            sender: The email address the message is being sent from.
            to: The email address the message is being sent to.
            subject: The subject line of the email.
            msg_html: The HTML message of the email.
            msg_plain: The plain text alternate message of the email. This is
                often displayed on slow or old browsers, or if the HTML message
                is not provided.
            cc: The list of email addresses to be cc'd.
            bcc: The list of email addresses to be bcc'd.
            attachments: The list of attachment file names.
            signature: Whether the account signature should be added to the
                message.
            user_id: The address of the sending account. 'me' for the
                default address associated with the account.

        Returns:
            The Message object representing the sent message.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        msg = self._create_message(
            sender,
            to,
            subject,
            msg_html,
            msg_plain,
            cc=cc,
            bcc=bcc,
            attachments=attachments,
            signature=signature,
            user_id=user_id,
        )

        req = self._messages.send(userId="me", body=msg)
        res = req.execute()
        return self._build_message_from_ref(user_id, res, "reference")

    def get_unread_inbox(
        self,
        user_id: str = "me",
        labels: Optional[list[Label]] = None,
        query: str = "",
        attachment_format: ATTACHMENT_FORMAT = "reference",
        message_format: MESSAGE_FORMAT = "full",
    ) -> list[Message]:
        """
        Gets unread messages from your inbox.

        Args:
            user_id: The user's email address. By default, the authenticated
                user.
            labels: Labels that messages must match.
            query: A Gmail query to match.
            attachment_format: Accepted values are 'ignore' which completely
                ignores all attachments, 'reference' which includes attachment
                information but does not download the data, and 'download' which
                downloads the attachment data to store locally. Default
                'reference'.

        Returns:
            A list of message objects.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        labels = labels or []

        labels.append(label.INBOX)
        return self.get_unread_messages(user_id, labels, query, attachment_format, message_format=message_format)

    def get_starred_messages(
        self,
        user_id: str = "me",
        labels: Optional[list[Label]] = None,
        query: str = "",
        attachment_format: ATTACHMENT_FORMAT = "reference",
        include_spam_trash: bool = False,
        message_format: MESSAGE_FORMAT = "full",
    ) -> list[Message]:
        """
        Gets starred messages from your account.

        Args:
            user_id: The user's email address. By default, the authenticated
                user.
            labels: Label IDs messages must match.
            query: A Gmail query to match.
            attachments: accepted values are 'ignore' which completely
                ignores all attachments, 'reference' which includes attachment
                information but does not download the data, and 'download' which
                downloads the attachment data to store locally. Default
                'reference'.
            include_spam_trash: Whether to include messages from spam or trash.

        Returns:
            A list of message objects.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        labels = labels or []

        labels.append(label.STARRED)
        return self.get_messages(
            user_id=user_id,
            labels=labels,
            query=query,
            attachment_format=attachment_format,
            include_spam_trash=include_spam_trash,
            message_format=message_format,
        )

    def get_important_messages(
        self,
        user_id: str = "me",
        labels: Optional[list[Label]] = None,
        query: str = "",
        attachment_format: ATTACHMENT_FORMAT = "reference",
        include_spam_trash: bool = False,
        message_format: MESSAGE_FORMAT = "full",
    ) -> list[Message]:
        """
        Gets messages marked important from your account.

        Args:
            user_id: The user's email address. By default, the authenticated
                user.
            labels: Label IDs messages must match.
            query: A Gmail query to match.
            attachment_format: accepted values are 'ignore' which completely
                ignores all attachments, 'reference' which includes attachment
                information but does not download the data, and 'download' which
                downloads the attachment data to store locally. Default
                'reference'.
            include_spam_trash: Whether to include messages from spam or trash.

        Returns:
            A list of message objects.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        labels = labels or []

        labels.append(label.IMPORTANT)
        return self.get_messages(
            user_id=user_id,
            labels=labels,
            query=query,
            attachment_format=attachment_format,
            include_spam_trash=include_spam_trash,
            message_format=message_format,
        )

    def get_unread_messages(
        self,
        user_id: str = "me",
        labels: Optional[list[Label]] = None,
        query: str = "",
        attachment_format: ATTACHMENT_FORMAT = "reference",
        include_spam_trash: bool = False,
        message_format: MESSAGE_FORMAT = "full",
    ) -> list[Message]:
        """
        Gets unread messages from your account.

        Args:
            user_id: The user's email address. By default, the authenticated
                user.
            labels: Label IDs messages must match.
            query: A Gmail query to match.
            attachment_format: accepted values are 'ignore' which completely
                ignores all attachments, 'reference' which includes attachment
                information but does not download the data, and 'download' which
                downloads the attachment data to store locally. Default
                'reference'.
            include_spam_trash: Whether to include messages from spam or trash.

        Returns:
            A list of message objects.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        labels = labels or []

        labels.append(label.UNREAD)
        return self.get_messages(
            user_id=user_id,
            labels=labels,
            query=query,
            attachment_format=attachment_format,
            include_spam_trash=include_spam_trash,
            message_format=message_format,
        )

    def get_drafts(
        self,
        user_id: str = "me",
        labels: Optional[list[Label]] = None,
        query: str = "",
        attachment_format: ATTACHMENT_FORMAT = "reference",
        include_spam_trash: bool = False,
        message_format: MESSAGE_FORMAT = "full",
    ) -> list[Message]:
        """
        Gets drafts saved in your account.

        Args:
            user_id: The user's email address. By default, the authenticated
                user.
            labels: Label IDs messages must match.
            query: A Gmail query to match.
            attachment_format: accepted values are 'ignore' which completely
                ignores all attachments, 'reference' which includes attachment
                information but does not download the data, and 'download' which
                downloads the attachment data to store locally. Default
                'reference'.
            include_spam_trash: Whether to include messages from spam or trash.

        Returns:
            A list of message objects.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        labels = labels or []

        labels.append(label.DRAFT)
        return self.get_messages(
            user_id=user_id,
            labels=labels,
            query=query,
            attachment_format=attachment_format,
            include_spam_trash=include_spam_trash,
            message_format=message_format,
        )

    def get_sent_messages(
        self,
        user_id: str = "me",
        labels: Optional[list[Label]] = None,
        query: str = "",
        attachment_format: ATTACHMENT_FORMAT = "reference",
        include_spam_trash: bool = False,
        message_format: MESSAGE_FORMAT = "full",
    ) -> list[Message]:
        """
        Gets sent messages from your account.

         Args:
            user_id: The user's email address. By default, the authenticated
                user.
            labels: Label IDs messages must match.
            query: A Gmail query to match.
            attachment_format: accepted values are 'ignore' which completely
                ignores all attachments, 'reference' which includes attachment
                information but does not download the data, and 'download' which
                downloads the attachment data to store locally. Default
                'reference'.
            include_spam_trash: Whether to include messages from spam or trash.

        Returns:
            A list of message objects.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        labels = labels or []

        labels.append(label.SENT)
        return self.get_messages(
            user_id=user_id,
            labels=labels,
            query=query,
            attachment_format=attachment_format,
            include_spam_trash=include_spam_trash,
            message_format=message_format,
        )

    def get_trash_messages(
        self,
        user_id: str = "me",
        labels: Optional[list[Label]] = None,
        query: str = "",
        attachment_format: ATTACHMENT_FORMAT = "reference",
        message_format: MESSAGE_FORMAT = "full",
    ) -> list[Message]:
        """
        Gets messages in your trash from your account.

        Args:
            user_id: The user's email address. By default, the authenticated
                user.
            labels: Label IDs messages must match.
            query: A Gmail query to match.
            attachment_format: accepted values are 'ignore' which completely
                ignores all attachments, 'reference' which includes attachment
                information but does not download the data, and 'download' which
                downloads the attachment data to store locally. Default
                'reference'.

        Returns:
            A list of message objects.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        labels = labels or []

        labels.append(label.TRASH)
        return self.get_messages(
            user_id=user_id,
            labels=labels,
            query=query,
            attachment_format=attachment_format,
            include_spam_trash=True,
            message_format=message_format,
        )

    def get_spam_messages(
        self,
        user_id: str = "me",
        labels: Optional[list[Label]] = None,
        query: str = "",
        attachment_format: ATTACHMENT_FORMAT = "reference",
        message_format: MESSAGE_FORMAT = "full",
    ) -> list[Message]:
        """
        Gets messages marked as spam from your account.

        Args:
            user_id: The user's email address. By default, the authenticated
                user.
            labels: Label IDs messages must match.
            query: A Gmail query to match.
            attachment_format: accepted values are 'ignore' which completely
                ignores all attachments, 'reference' which includes attachment
                information but does not download the data, and 'download' which
                downloads the attachment data to store locally. Default
                'reference'.

        Returns:
            A list of message objects.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        labels = labels or []

        labels.append(label.SPAM)

        return self.get_messages(
            user_id=user_id,
            labels=labels,
            query=query,
            attachment_format=attachment_format,
            include_spam_trash=True,
            message_format=message_format,
        )

    def _get_references(
        self,
        user_id: str = "me",
        labels: Optional[list[Label]] = None,
        query: str = "",
        include_spam_trash: bool = False,
    ) -> list[MessageRef]:
        """
        Gets messages from your account.

        Args:
            user_id: the user's email address. Default 'me', the authenticated
                user.
            labels: label IDs messages must match.
            query: a Gmail query to match.
            include_spam_trash: whether to include messages from spam or trash.

        Returns:
            A list of reference objects.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        labels = labels or []

        labels_ids = [lbl.id if isinstance(lbl, Label) else lbl for lbl in labels]

        response = self._messages.list(
            userId=user_id, q=query, labelIds=labels_ids, includeSpamTrash=include_spam_trash
        ).execute()

        message_refs = []
        if "messages" in response:  # ensure request was successful
            message_refs.extend(response["messages"])

        while "nextPageToken" in response:
            page_token = response["nextPageToken"]
            response = self._messages.list(
                userId=user_id,
                q=query,
                labelIds=labels_ids,
                includeSpamTrash=include_spam_trash,
                pageToken=page_token,
            ).execute()

            message_refs.extend(response["messages"])

        return message_refs

    def get_messages(
        self,
        user_id: str = "me",
        labels: Optional[list[Label]] = None,
        query: str = "",
        attachment_format: ATTACHMENT_FORMAT = "reference",
        include_spam_trash: bool = False,
        message_format: MESSAGE_FORMAT = "full",
    ) -> list[Message]:
        """
        Gets messages from your account.

        Args:
            user_id: the user's email address. Default 'me', the authenticated
                user.
            labels: label IDs messages must match.
            query: a Gmail query to match.
            attachment_format: accepted values are 'ignore' which completely
                ignores all attachments, 'reference' which includes attachment
                information but does not download the data, and 'download' which
                downloads the attachment data to store locally. Default
                'reference'.
            include_spam_trash: whether to include messages from spam or trash.

        Returns:
            A list of message objects.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        message_refs = self._get_references(user_id, labels, query, include_spam_trash)

        return self._get_messages_from_refs(user_id, message_refs, attachment_format, message_format=message_format)

    def list_labels(self, user_id: str = "me") -> list[Label]:
        """
        Retrieves all labels for the specified user.

        These Label objects are to be used with other functions like
        modify_labels().

        Args:
            user_id: The user's email address. By default, the authenticated
                user.

        Returns:
            The list of Label objects.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        res = self.service.users().labels().list(userId=user_id).execute()

        labels = [Label(name=x["name"], id=x["id"]) for x in res["labels"]]
        return labels

    def create_label(self, name: str, user_id: str = "me") -> Label:
        """
        Creates a new label.

        Args:
            name: The display name of the new label.
            user_id: The user's email address. By default, the authenticated
                user.

        Returns:
            The created Label object.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """
        # TODO: In the future, can add the following fields:
        # "messageListVisibility"
        # "labelListVisibility"
        # "color"

        body = {"name": name}

        res = self.service.users().labels().create(userId=user_id, body=body).execute()
        return Label(res["name"], res["id"])

    def delete_label(self, label: Label, user_id: str = "me") -> None:
        """
        Deletes a label.

        Args:
            label: The label to delete.
            user_id: The user's email address. By default, the authenticated
                user.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        self.service.users().labels().delete(userId=user_id, id=label.id).execute()

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(max=4),
        after=after_log(LOGGER, logging.DEBUG),
        before=before_log(LOGGER, logging.DEBUG),
        before_sleep=before_sleep_log(LOGGER, logging.INFO),
    )
    def fetch_message(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        user_id: str,
        message_id: str,
        message_format: MESSAGE_FORMAT,
    ):
        url = GET_MSG_URL_TEMPLATE.format(user_id=user_id, message_id=message_id, message_format=message_format)
        response = client.get(url, headers=headers)
        response.raise_for_status()

        return response

    def fetch_all_messages(self, user_id: str, message_refs: list[dict], headers: dict, message_format: MESSAGE_FORMAT):
        with httpx.Client() as client, ThreadPoolExecutor() as pool:
            tasks = [
                pool.submit(self.fetch_message, client, headers, user_id, message["id"], message_format)
                for message in message_refs
            ]
            responses = [task.result() for task in tasks]

        return responses

    def _get_messages_from_refs(
        self,
        user_id: str,
        message_refs: list[MessageRef],
        attachment_format: ATTACHMENT_FORMAT = "reference",
        message_format: MESSAGE_FORMAT = "full",
    ) -> list[Message]:
        """
        Retrieves the actual messages from a list of references.

        Args:
            user_id: The account the messages belong to.
            message_refs: A list of message references with keys id, threadId.
            attachment_format: Accepted values are 'ignore' which completely ignores
                all attachments, 'reference' which includes attachment
                information but does not download the data, and 'download'
                which downloads the attachment data to store locally. Default
                'reference'.

        Returns:
            A list of Message objects.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        if not message_refs:
            return []

        # build a fake message to get the headers
        headers = self._messages.get(userId=user_id, id=1, format=message_format).headers

        # add the authorization header
        headers["Authorization"] = f"Bearer {self.creds.access_token}"

        responses = self.fetch_all_messages(user_id, message_refs, headers, message_format)

        message_refs = [response.json() for response in responses]

        messages = [
            self._build_message_from_ref(user_id, message, attachment_format, message_format=message_format)
            for message in message_refs
        ]

        return messages

    def _create_update_labels(
        self,
        to_add: Optional[Union[list[Label], list[str]]] = None,
        to_remove: Optional[Union[list[Label], list[str]]] = None,
    ) -> dict:
        """
        Creates an object for updating message label.

        Args:
            to_add: A list of labels to add.
            to_remove: A list of labels to remove.

        Returns:
            The modify labels object to pass to the Gmail API.

        """

        to_add = to_add or []
        to_remove = to_remove or []

        return {
            "addLabelIds": [lbl.id if isinstance(lbl, Label) else lbl for lbl in to_add],
            "removeLabelIds": [lbl.id if isinstance(lbl, Label) else lbl for lbl in to_remove],
        }

    def mark_messages_as_read(self, messages: list[Message]):
        """
        Marks messages as read.

        Args:
            messages: The messages to mark as read.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        body = self._create_update_labels([], [label.UNREAD])

        # build a fake message to get the headers
        headers = self._messages.modify(userId="me", id=1, body=body).headers
        headers["Authorization"] = f"Bearer {self.creds.access_token}"

        responses = self.update_all_messages("me", messages, headers, body)

        return responses

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(max=4),
        after=after_log(LOGGER, logging.DEBUG),
        before=before_log(LOGGER, logging.DEBUG),
        before_sleep=before_sleep_log(LOGGER, logging.INFO),
    )
    def update_message(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        user_id: str,
        message_id: str,
        body: dict,
    ):
        url = MODIFY_MSG_URL_TEMPLATE.format(user_id=user_id, message_id=message_id)
        response = client.post(url, headers=headers, json=body)
        response.raise_for_status()

        return response

    def update_all_messages(self, user_id: str, message_refs: list[dict], headers: dict, body: dict):
        with httpx.Client() as client, ThreadPoolExecutor() as pool:
            tasks = [
                pool.submit(self.update_message, client, headers, user_id, message.id, body) for message in message_refs
            ]
            responses = [task.result() for task in tasks]

        return responses

    def _get_and_build_message(
        self,
        user_id: str,
        message_id: str,
        message_format: MESSAGE_FORMAT = "full",
        attachment_format: ATTACHMENT_FORMAT = "reference",
    ) -> Message:
        """
        Retrieves and builds a message from the Gmail API.

        Args:
            user_id: The username of the account the message belongs to.
            message_id: The ID of the message to retrieve.
            message_format: The format of the message to retrieve. Accepted
                values are 'minimal', 'full', and 'metadata'. Default 'full'.
            attachment_format: Accepted values are 'ignore' which completely ignores
                all attachments, 'reference' which includes attachment
                information but does not download the data, and 'download' which
                downloads the attachment data to store locally. Default
                'reference'.

        Returns:
            The Message object.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        message = self._messages.get(userId=user_id, id=message_id, format=message_format).execute()
        return self._build_message_from_ref(user_id, message, attachment_format, message_format=message_format)

    def _build_message_from_ref(
        self,
        user_id: str,
        message: Message,
        attachment_format: ATTACHMENT_FORMAT = "reference",
        message_format: MESSAGE_FORMAT = "full",
    ) -> Message:
        """
        Creates a Message object from a reference.

        Args:
            user_id: The username of the account the message belongs to.
            message_ref: The message reference object returned from the Gmail API.
            attachment_format: Accepted values are 'ignore' which completely ignores
                all attachments, 'reference' which includes attachment
                information but does not download the data, and 'download' which
                downloads the attachment data to store locally. Default
                'reference'.

        Returns:
            The Message object.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        if message_format not in ["minimal", "full", "metadata"]:
            raise ValueError("Invalid message format. Must be 'minimal', 'full', or 'metadata'.")

        if message_format == "full":
            built_msg = self._build_message_from_full_ref(user_id, message, attachment_format)

        elif message_format == "metadata":
            built_msg = self._build_message_from_metadata_ref(user_id, message)

        elif message_format == "minimal":
            built_msg = self._build_message_from_minimal_ref(user_id, message)

        else:
            raise ValueError("Invalid message format. Must be 'minimal', 'full', or 'metadata'.")

        return built_msg

    def _build_message_from_metadata_ref(self, user_id: str, message: Message) -> Message:
        """
        Creates a Message object from a reference.

        Args:
            user_id: The username of the account the message belongs to.
            message_ref: The message reference object returned from the Gmail API.
            attachment_format: Accepted values are 'ignore' which completely ignores
                all attachments, 'reference' which includes attachment
                information but does not download the data, and 'download' which
                downloads the attachment data to store locally. Default
                'reference'.

        Returns:
            The Message object.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        msg_id = message["id"]
        thread_id = message["threadId"]
        label_ids = []
        if "labelIds" in message:
            label_ids = [self.labels[x] for x in message["labelIds"]]

        snippet = html.unescape(message["snippet"])

        payload = message["payload"]
        headers = payload["headers"]

        msg_hdrs = {hdr["name"]: hdr["value"] for hdr in headers}

        sender = msg_hdrs.get("From", "")
        recipient = msg_hdrs.get("To", "")
        subject = msg_hdrs.get("Subject", "")
        cc = msg_hdrs.get("Cc", "").split(", ")
        bcc = msg_hdrs.get("Bcc", "").split(", ")
        date = msg_hdrs.get("Date", "")

        with contextlib.suppress(Exception):
            date = str(parser.parse(date).astimezone())

        return Message(
            service=self.service,
            creds=self.creds,
            user_id=user_id,
            msg_id=msg_id,
            thread_id=thread_id,
            recipient=recipient,
            sender=sender,
            subject=subject,
            date=date,
            snippet=snippet,
            plain=None,
            html=None,
            label_ids=label_ids,
            attachments=[],
            headers=msg_hdrs,
            cc=cc,
            bcc=bcc,
        )

    def _build_message_from_minimal_ref(self, user_id: str, message: Message) -> Message:
        """
        Creates a Message object from a reference.

        Args:
            user_id: The username of the account the message belongs to.
            message: The message reference object returned from the Gmail API.
            attachment_format: Accepted values are 'ignore' which completely ignores
                all attachments, 'reference' which includes attachment
                information but does not download the data, and 'download' which
                downloads the attachment data to store locally. Default
                'reference'.

        Returns:
            The Message object.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        msg_id = message["id"]
        thread_id = message["threadId"]
        label_ids = []
        if "labelIds" in message:
            label_ids = [self.labels[x] for x in message["labelIds"]]

        snippet = html.unescape(message["snippet"])

        date_epoch = message.get("internalDate")
        dtme = datetime.fromtimestamp(int(date_epoch) / 1000)  # noqa
        dtme_str = str(dtme.astimezone())

        return Message(
            service=self.service,
            creds=self.creds,
            user_id=user_id,
            msg_id=msg_id,
            thread_id=thread_id,
            recipient="",
            sender="",
            subject="",
            date=dtme_str,
            snippet=snippet,
            label_ids=label_ids,
        )

    def _build_message_from_full_ref(
        self,
        user_id: str,
        message: Message,
        attachment_format: ATTACHMENT_FORMAT = "reference",
    ) -> Message:
        """
        Creates a Message object from a reference.

        Args:
            user_id: The username of the account the message belongs to.
            message: The message reference object returned from the Gmail API.
            attachment_format: Accepted values are 'ignore' which completely ignores
                all attachments, 'reference' which includes attachment
                information but does not download the data, and 'download' which
                downloads the attachment data to store locally. Default
                'reference'.

        Returns:
            The Message object.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        msg_id = message["id"]
        thread_id = message["threadId"]
        label_ids = []
        if "labelIds" in message:
            label_ids = [self.labels[x] for x in message["labelIds"]]

        snippet = html.unescape(message["snippet"])

        payload = message["payload"]
        headers = payload["headers"]

        msg_hdrs = {hdr["name"]: hdr["value"] for hdr in headers}

        sender = msg_hdrs.get("From", "")
        recipient = msg_hdrs.get("To", "")
        subject = msg_hdrs.get("Subject", "")
        cc = msg_hdrs.get("Cc", "").split(", ")
        bcc = msg_hdrs.get("Bcc", "").split(", ")
        date = msg_hdrs.get("Date", "")

        with contextlib.suppress(Exception):
            date = str(parser.parse(date).astimezone())

        parts = self._evaluate_message_payload(payload, user_id, msg_id, attachment_format)

        plain_msg = None
        html_msg = None
        attms = []

        plain_msgs = [part["body"] for part in parts if part["part_type"] == "plain"]
        html_msgs = [part["body"] for part in parts if part["part_type"] == "html"]
        raw_attachments = [part for part in parts if part["part_type"] == "attachment"]

        plain_msg = "\n".join(plain_msgs)
        html_msg = "<br/>".join(html_msgs)

        for part in raw_attachments:
            attm = Attachment(
                self.service,
                user_id,
                msg_id,
                part["attachment_id"],
                part["filename"],
                part["filetype"],
                part["data"],
            )
            attms.append(attm)

        return Message(
            self.service,
            self.creds,
            user_id,
            msg_id,
            thread_id,
            recipient,
            sender,
            subject,
            date,
            snippet,
            plain_msg,
            html_msg,
            label_ids,
            attms,
            msg_hdrs,
            cc,
            bcc,
        )

    def _evaluate_message_payload(
        self,
        payload: dict,
        user_id: str,
        msg_id: str,
        attachment_format: ATTACHMENT_FORMAT = "reference",
    ) -> list[dict]:
        """
        Recursively evaluates a message payload.

        Args:
            payload: The message payload object (response from Gmail API).
            user_id: The current account address (default 'me').
            msg_id: The id of the message.
            attachment_format: Accepted values are 'ignore' which completely ignores
                all attachments, 'reference' which includes attachment
                information but does not download the data, and 'download' which
                downloads the attachment data to store locally. Default
                'reference'.

        Returns:
            A list of message parts.

        Raises:
            googleapiclient.errors.HttpError: There was an error executing the
                HTTP request.

        """

        if "attachmentId" in payload["body"]:  # if it's an attachment
            if attachment_format == "ignore":
                return []

            att_id = payload["body"]["attachmentId"]
            filename = payload["filename"]
            if not filename:
                filename = "unknown"

            obj = {
                "part_type": "attachment",
                "filetype": payload["mimeType"],
                "filename": filename,
                "attachment_id": att_id,
                "data": None,
            }

            if attachment_format == "reference":
                return [obj]

            # attachment_format == 'download'
            if "data" in payload["body"]:
                data = payload["body"]["data"]
            else:
                res = (
                    self.service.users()
                    .messages()
                    .attachments()
                    .get(userId=user_id, messageId=msg_id, id=att_id)
                    .execute()
                )
                data = res["data"]

            file_data = base64.urlsafe_b64decode(data)
            obj["data"] = file_data
            return [obj]

        if payload["mimeType"] == "text/html":
            data = payload["body"]["data"]
            data = base64.urlsafe_b64decode(data)
            body = BeautifulSoup(data, "lxml", from_encoding="utf-8").body
            return [{"part_type": "html", "body": str(body)}]

        if payload["mimeType"] == "text/plain":
            data = payload["body"]["data"]
            data = base64.urlsafe_b64decode(data)
            body = data.decode("UTF-8")
            return [{"part_type": "plain", "body": body}]

        if payload["mimeType"].startswith("multipart"):
            ret = []
            if "parts" in payload:
                for part in payload["parts"]:
                    ret.extend(self._evaluate_message_payload(part, user_id, msg_id, attachment_format))
            return ret

        return []

    def _create_message(
        self,
        sender: str,
        to: str,
        subject: str = "",
        msg_html: Optional[str] = None,
        msg_plain: Optional[str] = None,
        cc: Optional[list[str]] = None,
        bcc: Optional[list[str]] = None,
        attachments: Optional[list[str]] = None,
        signature: bool = False,
        user_id: str = "me",
    ) -> dict:
        """
        Creates the raw email message to be sent.

        Args:
            sender: The email address the message is being sent from.
            to: The email address the message is being sent to.
            subject: The subject line of the email.
            msg_html: The HTML message of the email.
            msg_plain: The plain text alternate message of the email (for slow
                or old browsers).
            cc: The list of email addresses to be Cc'd.
            bcc: The list of email addresses to be Bcc'd
            attachments: A list of attachment file paths.
            signature: Whether the account signature should be added to the
                message. Will add the signature to your HTML message only, or a
                create a HTML message if none exists.

        Returns:
            The message dict.

        """

        msg = MIMEMultipart("mixed" if attachments else "alternative")
        msg["To"] = to
        msg["From"] = sender
        msg["Subject"] = subject

        if cc:
            msg["Cc"] = ", ".join(cc)

        if bcc:
            msg["Bcc"] = ", ".join(bcc)

        if signature:
            m = re.match(r".+\s<(?P<addr>.+@.+\..+)>", sender)
            address = m.group("addr") if m else sender
            account_sig = self._get_alias_info(address, user_id)["signature"]

            if msg_html is None:
                msg_html = ""

            msg_html += "<br /><br />" + account_sig

        attach_plain = MIMEMultipart("alternative") if attachments else msg
        attach_html = MIMEMultipart("related") if attachments else msg

        if msg_plain:
            attach_plain.attach(MIMEText(msg_plain, "plain"))

        if msg_html:
            attach_html.attach(MIMEText(msg_html, "html"))

        if attachments:
            attach_plain.attach(attach_html)
            msg.attach(attach_plain)

            self._ready_message_with_attachments(msg, attachments)

        return {"raw": base64.urlsafe_b64encode(msg.as_string().encode()).decode()}

    def _ready_message_with_attachments(self, msg: MIMEMultipart, attachments: list[str]) -> None:
        """
        Converts attachment filepaths to MIME objects and adds them to msg.

        Args:
            msg: The message to add attachments to.
            attachments: A list of attachment file paths.

        """

        for filepath in attachments:
            content_type, encoding = mimetypes.guess_type(filepath)

            if content_type is None or encoding is not None:
                content_type = "application/octet-stream"

            main_type, sub_type = content_type.split("/", 1)
            with open(filepath, "rb") as file:
                raw_data = file.read()

                attm: MIMEBase
                if main_type == "text":
                    attm = MIMEText(raw_data.decode("UTF-8"), _subtype=sub_type)
                elif main_type == "image":
                    attm = MIMEImage(raw_data, _subtype=sub_type)
                elif main_type == "audio":
                    attm = MIMEAudio(raw_data, _subtype=sub_type)
                elif main_type == "application":
                    attm = MIMEApplication(raw_data, _subtype=sub_type)
                else:
                    attm = MIMEBase(main_type, sub_type)
                    attm.set_payload(raw_data)

            fname = Path(filepath).name
            attm.add_header("Content-Disposition", "attachment", filename=fname)
            msg.attach(attm)

    def _get_alias_info(self, send_as_email: str, user_id: str = "me") -> dict:
        """
        Returns the alias info of an email address on the authenticated
        account.

        Response data is of the following form:
        {
            "sendAsEmail": string,
            "displayName": string,
            "replyToAddress": string,
            "signature": string,
            "isPrimary": boolean,
            "isDefault": boolean,
            "treatAsAlias": boolean,
            "smtpMsa": {
                "host": string,
                "port": integer,
                "username": string,
                "password": string,
                "securityMode": string
            },
            "verificationStatus": string
        }

        Args:
            send_as_email: The alias account information is requested for
                (could be the primary account).
            user_id: The user ID of the authenticated user the account the
                alias is for (default "me").

        Returns:
            The dict of alias info associated with the account.

        """

        req = self.service.users().settings().sendAs().get(sendAsEmail=send_as_email, userId=user_id)

        res = req.execute()
        return res
