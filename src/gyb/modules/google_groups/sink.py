"""Google Groups Migration API Sink module."""

from __future__ import annotations

from types import TracebackType
from typing import Self

from gyb.core.capabilities import Capability
from gyb.core.exceptions import ConfigurationError, PermanentTransferError
from gyb.core.models import Message, TransferResult, TransferStatus
from gyb.modules.gmail.sanitizer import sanitize_rfc822_message
from gyb.modules.google_groups.client import (
    GROUPS_MAX_MESSAGE_BYTES,
    GroupsBadMessageError,
    GroupsMigrationClient,
)


class GoogleGroupsSink:
    """Imports messages into a Google Workspace Group archive over HTTP/2."""

    def __init__(
        self,
        client: GroupsMigrationClient,
        *,
        cleanup: bool = False,
        cleanup_from: str | None = None,
        close_transport: bool = True,
    ) -> None:
        self._client = client
        self._cleanup = cleanup
        self._cleanup_from = cleanup_from
        self._close_transport = close_transport
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
    def client(self) -> GroupsMigrationClient:
        return self._client

    @property
    def capabilities(self) -> Capability:
        return (
            Capability.STREAMING_INSERT
            | Capability.MULTIPLEXED_STREAMS
            | Capability.SERVER_DEDUPLICATION
        )

    def connect(self) -> None:
        self._connected = True

    def import_message(self, message: Message) -> TransferResult:
        if not self._connected:
            raise ConfigurationError("GoogleGroupsSink is not connected.")
        if message.size_bytes > GROUPS_MAX_MESSAGE_BYTES:
            raise PermanentTransferError(
                f"Message {message.source_id!r} ({message.size_bytes} bytes) exceeds "
                f"Google Groups maximum size of {GROUPS_MAX_MESSAGE_BYTES} bytes."
            )

        payload = message.raw_rfc822
        was_sanitized = False
        if self._cleanup:
            payload, changes = sanitize_rfc822_message(
                payload,
                cleanup_from=self._cleanup_from,
                fallback_date=message.internal_date,
            )
            was_sanitized = bool(changes)

        try:
            self._client.insert_archive_message(payload)
        except GroupsBadMessageError:
            sanitized_payload, changes = sanitize_rfc822_message(
                payload,
                cleanup_from=self._cleanup_from,
                fallback_date=message.internal_date,
            )
            if not changes:
                raise
            was_sanitized = True
            self._client.insert_archive_message(sanitized_payload)
            payload = sanitized_payload

        return TransferResult(
            source_id=message.source_id,
            status=TransferStatus.SUCCESS,
            destination_id=self._client.group_email,
            bytes_transferred=len(payload),
            sanitized=was_sanitized,
        )

    def close(self) -> None:
        self._connected = False
        if self._close_transport:
            self._client.transport.close()
