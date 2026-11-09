"""Gmail API Source and Sink module."""

from ngyb.modules.gmail.client import (
    GmailBadRequestError,
    GmailClient,
    build_multipart_related,
    parse_google_api_error,
    parse_retry_after,
)
from ngyb.modules.gmail.labels import (
    GMAIL_IMPORTABLE_SYSTEM_LABELS,
    GMAIL_SYSTEM_LABELS,
    RESERVED_USER_LABEL_ROOTS,
    GmailLabelManager,
    transform_label_for_gmail,
)
from ngyb.modules.gmail.sanitizer import GMAIL_MAX_MESSAGE_BYTES, sanitize_rfc822_message
from ngyb.modules.gmail.sink import GmailSink
from ngyb.modules.gmail.source import GmailSource

__all__ = [
    "GMAIL_IMPORTABLE_SYSTEM_LABELS",
    "GMAIL_MAX_MESSAGE_BYTES",
    "GMAIL_SYSTEM_LABELS",
    "GmailBadRequestError",
    "GmailClient",
    "GmailLabelManager",
    "GmailSink",
    "GmailSource",
    "RESERVED_USER_LABEL_ROOTS",
    "build_multipart_related",
    "parse_google_api_error",
    "parse_retry_after",
    "sanitize_rfc822_message",
    "transform_label_for_gmail",
]
