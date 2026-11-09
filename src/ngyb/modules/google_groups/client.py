"""Google Groups Migration API v1 client over HTTP/2 streams."""

from __future__ import annotations

import json
import urllib.parse
from typing import Any

from ngyb.auth.transport import ModernAuthorizedHttp
from ngyb.core.exceptions import PermanentTransferError, TransientTransferError
from ngyb.modules.gmail.client import (
    RETRYABLE_GMAIL_REASONS,
    parse_google_api_error,
    parse_retry_after,
)

GROUPS_UPLOAD_BASE = "https://www.googleapis.com/upload/groups/v1/groups"
GROUPS_MAX_MESSAGE_BYTES = 25 * 1024 * 1024


class GroupsBadMessageError(PermanentTransferError):
    """Raised when Groups Migration API rejects an RFC 822 message as invalid (400)."""


class GroupsMigrationClient:
    """Uploads RFC 822 archive messages to Google Groups over HTTP/2."""

    def __init__(self, transport: ModernAuthorizedHttp, group_email: str) -> None:
        self._transport = transport
        self._group_email = group_email
        self._encoded_group = urllib.parse.quote(group_email, safe="@.")
        self._last_http_version: int | None = None

    @property
    def transport(self) -> ModernAuthorizedHttp:
        return self._transport

    @property
    def group_email(self) -> str:
        return self._group_email

    @property
    def last_http_version(self) -> int | None:
        return self._last_http_version

    def insert_archive_message(self, raw_rfc822: bytes) -> dict[str, Any]:
        """POST raw RFC 822 payload to groupsmigration.archive.insert."""
        url = f"{GROUPS_UPLOAD_BASE}/{self._encoded_group}/archive?uploadType=media"
        try:
            response, content = self._transport.request(
                url,
                method="POST",
                body=raw_rfc822,
                headers={"Content-Type": "message/rfc822"},
            )
        except OSError as exc:
            raise TransientTransferError(f"Groups Migration transport error: {exc}") from exc

        self._last_http_version = getattr(response, "version", None)
        status = int(getattr(response, "status", 200))
        if status >= 400:
            msg, reasons = parse_google_api_error(content)
            retry_after = parse_retry_after(response)
            if status in {429, 500, 502, 503, 504} or (
                status == 403 and any(r in RETRYABLE_GMAIL_REASONS for r in reasons)
            ):
                raise TransientTransferError(
                    f"Groups Migration HTTP {status}: {msg}",
                    retry_after=retry_after,
                )
            if status == 400:
                raise GroupsBadMessageError(f"Groups Migration 400: {msg}")
            raise PermanentTransferError(f"Groups Migration HTTP {status}: {msg}")

        data = dict(json.loads(content.decode("utf-8"))) if content else {}
        resp_code = str(data.get("responseCode", "SUCCESS"))
        if resp_code == "SUCCESS":
            return data
        if resp_code in {"INVALID_MESSAGE", "INVALID_HEADER"}:
            raise GroupsBadMessageError(f"Groups Migration responseCode={resp_code}")
        if resp_code in {"BACKEND_ERROR", "RATE_LIMIT_EXCEEDED"}:
            raise TransientTransferError(f"Groups Migration responseCode={resp_code}")
        raise PermanentTransferError(f"Groups Migration responseCode={resp_code}")
