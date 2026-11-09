"""Gmail API Source and Sink module."""

from gyb.modules.gmail.client import (
    RESUMABLE_CHUNK_SIZE,
    RESUMABLE_THRESHOLD_BYTES,
    RETRYABLE_GOOGLE_REASONS,
    GmailBadRequestError,
    GmailClient,
    GmailNotFoundError,
    extract_http_error_reasons,
    parse_retry_after,
    translate_google_http_error,
)
from gyb.modules.gmail.labels import (
    GMAIL_IMPORTABLE_SYSTEM_LABELS,
    GMAIL_SYSTEM_LABELS,
    RESERVED_USER_LABEL_ROOTS,
    GmailLabelManager,
    transform_label_for_gmail,
)
from gyb.modules.gmail.sanitizer import GMAIL_MAX_MESSAGE_BYTES, sanitize_rfc822_message
from gyb.modules.gmail.sink import GmailSink
from gyb.modules.gmail.source import GmailSource

__all__ = [
    "GMAIL_IMPORTABLE_SYSTEM_LABELS",
    "GMAIL_MAX_MESSAGE_BYTES",
    "GMAIL_SYSTEM_LABELS",
    "GmailBadRequestError",
    "GmailClient",
    "GmailLabelManager",
    "GmailNotFoundError",
    "GmailSink",
    "GmailSource",
    "RESERVED_USER_LABEL_ROOTS",
    "RESUMABLE_CHUNK_SIZE",
    "RESUMABLE_THRESHOLD_BYTES",
    "RETRYABLE_GOOGLE_REASONS",
    "extract_http_error_reasons",
    "parse_retry_after",
    "sanitize_rfc822_message",
    "transform_label_for_gmail",
    "translate_google_http_error",
]
