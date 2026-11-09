"""Gmail API Sink module with 400 header sanitization, label mapping, and draft support."""

from __future__ import annotations

from types import TracebackType
from typing import Any, Self

from gyb.core.capabilities import Capability
from gyb.core.exceptions import ConfigurationError, PermanentTransferError
from gyb.core.models import Message, TransferResult, TransferStatus
from gyb.modules.gmail.client import (
    GmailBadRequestError,
    GmailClient,
    GmailNotFoundError,
)
from gyb.modules.gmail.labels import GmailLabelManager
from gyb.modules.gmail.sanitizer import GMAIL_MAX_MESSAGE_BYTES, sanitize_rfc822_message


class GmailSink:
    """Imports messages into a Gmail mailbox over HTTP/2 streams."""

    def __init__(
        self,
        client: GmailClient,
        *,
        strip_labels: bool = False,
        label_prefix: str | None = None,
        label_restored: str | None = None,
        cleanup: bool = False,
        cleanup_from: str | None = None,
        use_insert: bool = False,
        never_mark_spam: bool = True,
        preserve_threads: bool = False,
        close_transport: bool = True,
    ) -> None:
        self._client = client
        self._strip_labels = strip_labels
        self._label_prefix = label_prefix
        self._label_restored = label_restored
        self._cleanup = cleanup
        self._cleanup_from = cleanup_from
        self._use_insert = use_insert
        self._never_mark_spam = never_mark_spam
        self._preserve_threads = preserve_threads
        self._close_transport = close_transport
        self._labels = GmailLabelManager(client)
        self._connected = False

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def client(self) -> GmailClient:
        return self._client

    @property
    def label_manager(self) -> GmailLabelManager:
        return self._labels

    @property
    def capabilities(self) -> Capability:
        caps = (
            Capability.STREAMING_INSERT
            | Capability.MULTIPLEXED_STREAMS
            | Capability.LABEL_SUPPORT
            | Capability.SERVER_DEDUPLICATION
        )
        if self._preserve_threads:
            caps |= Capability.PRESERVE_THREAD_ID
        return caps

    def connect(self) -> None:
        self._labels.refresh()
        self._connected = True

    def _upload_once(
        self,
        raw_bytes: bytes,
        *,
        label_ids: list[str],
        thread_id: str | None,
        is_draft: bool,
        is_deleted: bool,
        use_insert: bool,
    ) -> dict[str, Any]:
        if is_draft:
            return self._client.create_draft(
                raw_bytes,
                label_ids=label_ids,
                thread_id=thread_id,
            )
        return self._client.import_message(
            raw_bytes,
            label_ids=label_ids,
            thread_id=thread_id,
            never_mark_spam=self._never_mark_spam,
            deleted=is_deleted,
            use_insert=use_insert,
        )

    def _upload_payload(
        self,
        raw_bytes: bytes,
        *,
        label_ids: list[str],
        thread_id: str | None,
        is_draft: bool,
        is_deleted: bool,
        use_insert: bool,
    ) -> dict[str, Any]:
        try:
            return self._upload_once(
                raw_bytes,
                label_ids=label_ids,
                thread_id=thread_id,
                is_draft=is_draft,
                is_deleted=is_deleted,
                use_insert=use_insert,
            )
        except GmailNotFoundError:
            if thread_id is None:
                raise
        except GmailBadRequestError as exc:
            if thread_id is None or "thread" not in str(exc).lower():
                raise
        # Cross-mailbox --preserve-threads: foreign/invalid threadId rejected by target mailbox
        return self._upload_once(
            raw_bytes,
            label_ids=label_ids,
            thread_id=None,
            is_draft=is_draft,
            is_deleted=is_deleted,
            use_insert=use_insert,
        )

    def import_message(self, message: Message) -> TransferResult:
        if not self._connected:
            raise ConfigurationError("GmailSink is not connected.")
        if message.size_bytes > GMAIL_MAX_MESSAGE_BYTES:
            raise PermanentTransferError(
                f"Message {message.source_id!r} ({message.size_bytes} bytes) exceeds "
                f"Gmail maximum size of {GMAIL_MAX_MESSAGE_BYTES} bytes."
            )

        label_ids, label_is_draft = self._labels.prepare_import_labels(
            message.labels,
            strip_labels=self._strip_labels,
            label_prefix=self._label_prefix,
            label_restored=self._label_restored,
        )
        is_draft = message.is_draft or label_is_draft
        thread_id = message.thread_id if self._preserve_threads else None

        payload_bytes = message.raw_rfc822
        was_sanitized = False
        if self._cleanup:
            payload_bytes, changes = sanitize_rfc822_message(
                payload_bytes,
                cleanup_from=self._cleanup_from,
                fallback_date=message.internal_date,
            )
            was_sanitized = bool(changes)

        try:
            resp = self._upload_payload(
                payload_bytes,
                label_ids=label_ids,
                thread_id=thread_id,
                is_draft=is_draft,
                is_deleted=message.is_deleted,
                use_insert=self._use_insert,
            )
        except GmailBadRequestError:
            sanitized_bytes, changes = sanitize_rfc822_message(
                payload_bytes,
                cleanup_from=self._cleanup_from,
                fallback_date=message.internal_date,
            )
            was_sanitized = was_sanitized or bool(changes)
            try:
                resp = self._upload_payload(
                    sanitized_bytes,
                    label_ids=label_ids,
                    thread_id=thread_id,
                    is_draft=is_draft,
                    is_deleted=message.is_deleted,
                    use_insert=self._use_insert,
                )
            except GmailBadRequestError:
                if is_draft or self._use_insert:
                    raise
                # Final fallback: messages.insert with receivedTime when dateHeader is rejected
                resp = self._upload_payload(
                    sanitized_bytes,
                    label_ids=label_ids,
                    thread_id=thread_id,
                    is_draft=False,
                    is_deleted=message.is_deleted,
                    use_insert=True,
                )
            payload_bytes = sanitized_bytes

        dest_id = str(
            resp.get("message", {}).get("id")
            if is_draft and isinstance(resp.get("message"), dict)
            else resp.get("id", "")
        )
        return TransferResult(
            source_id=message.source_id,
            status=TransferStatus.SUCCESS,
            destination_id=dest_id or None,
            bytes_transferred=len(payload_bytes),
            sanitized=was_sanitized,
        )

    def close(self) -> None:
        self._connected = False
        if self._close_transport:
            self._client.transport.close()
