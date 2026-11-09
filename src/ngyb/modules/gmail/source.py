"""Gmail API Source module streaming mailbox messages over HTTP/2."""

from __future__ import annotations

import base64
from collections.abc import Iterator
from datetime import UTC, datetime

from ngyb.core.capabilities import Capability
from ngyb.core.exceptions import ConfigurationError, PermanentTransferError
from ngyb.core.models import Message
from ngyb.modules.gmail.client import GmailClient
from ngyb.modules.gmail.labels import SKIPPED_SOURCE_LABELS, GmailLabelManager
from ngyb.modules.local.schema import extract_msgid_and_date


def _decode_base64url(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


class GmailSource:
    """Streams message IDs and raw RFC 822 payloads from Gmail over HTTP/2."""

    def __init__(
        self,
        client: GmailClient,
        *,
        include_spam_trash: bool = False,
        close_transport: bool = True,
    ) -> None:
        self._client = client
        self._include_spam_trash = include_spam_trash
        self._close_transport = close_transport
        self._labels = GmailLabelManager(client)
        self._connected = False

    @property
    def client(self) -> GmailClient:
        return self._client

    @property
    def capabilities(self) -> Capability:
        return (
            Capability.STREAMING_FETCH
            | Capability.MULTIPLEXED_STREAMS
            | Capability.LABEL_SUPPORT
            | Capability.PRESERVE_THREAD_ID
            | Capability.QUERY_FILTERING
        )

    def connect(self) -> None:
        self._labels.refresh()
        self._connected = True

    def list_messages(self, query: str | None = None) -> Iterator[str]:
        if not self._connected:
            raise ConfigurationError("GmailSource is not connected.")
        effective_query = "-label:CHAT" if not query else f"({query}) -label:CHAT"
        yield from self._client.list_messages(
            query=effective_query,
            include_spam_trash=self._include_spam_trash,
        )

    def fetch_message(self, source_id: str) -> Message:
        if not self._connected:
            raise ConfigurationError("GmailSource is not connected.")
        payload = self._client.get_message(source_id, fmt="raw")
        raw_b64 = payload.get("raw")
        if not raw_b64:
            raise PermanentTransferError(f"Gmail message {source_id!r} missing raw payload.")

        raw_bytes = _decode_base64url(str(raw_b64))
        raw_label_ids = [str(lid) for lid in payload.get("labelIds", [])]
        resolved_labels = tuple(
            name
            for lid in raw_label_ids
            if (name := self._labels.resolve_id_to_name(lid)).upper() not in SKIPPED_SOURCE_LABELS
        )

        msgid, header_dt = extract_msgid_and_date(raw_bytes)
        internal_dt = header_dt
        internal_ms = payload.get("internalDate")
        if internal_ms is not None:
            try:
                internal_dt = datetime.fromtimestamp(int(internal_ms) / 1000.0, tz=UTC)
            except (TypeError, ValueError, OSError):
                internal_dt = header_dt

        thread_id = str(payload["threadId"]) if payload.get("threadId") else None
        is_draft = any(lbl.upper() == "DRAFT" for lbl in resolved_labels)
        return Message(
            source_id=str(payload.get("id", source_id)),
            raw_rfc822=raw_bytes,
            rfc822_msgid=msgid,
            internal_date=internal_dt,
            labels=resolved_labels,
            thread_id=thread_id,
            is_draft=is_draft,
        )

    def close(self) -> None:
        self._connected = False
        if self._close_transport:
            self._client.transport.close()
