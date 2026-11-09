"""Google Groups Migration API v1 client built on google-api-python-client over HTTP/2."""

from __future__ import annotations

from collections.abc import Mapping
from io import BytesIO
from typing import Any

import modern_httplib2
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError, MediaUploadSizeError
from googleapiclient.http import MediaIoBaseUpload

from gyb.auth.transport import ModernAuthorizedHttp
from gyb.core.exceptions import PermanentTransferError, TransientTransferError
from gyb.modules.gmail.client import translate_google_http_error

GROUPS_MAX_MESSAGE_BYTES = 25 * 1024 * 1024


class GroupsBadMessageError(PermanentTransferError):
    """Raised when Groups Migration API rejects an RFC 822 message as invalid (400)."""


class GroupsMigrationClient:
    """Uploads RFC 822 archive messages to Google Groups via Discovery API over HTTP/2."""

    def __init__(
        self,
        transport: ModernAuthorizedHttp,
        group_email: str,
        *,
        service: Any | None = None,
    ) -> None:
        self._transport = transport
        self._group_email = group_email
        self._service = (
            service
            if service is not None
            else build("groupsmigration", "v1", http=transport, cache_discovery=False)
        )
        self._archive = self._service.archive()

    @property
    def transport(self) -> ModernAuthorizedHttp:
        return self._transport

    @property
    def service(self) -> Any:
        return self._service

    @property
    def group_email(self) -> str:
        return self._group_email

    @property
    def last_http_version(self) -> str | None:
        """HTTP protocol version negotiated on the most recent API response."""
        return self._transport.last_http_version

    def insert_archive_message(self, raw_rfc822: bytes) -> dict[str, Any]:
        """Upload raw RFC 822 payload via groupsmigration.archive.insert."""
        try:
            media = MediaIoBaseUpload(
                BytesIO(raw_rfc822),
                mimetype="message/rfc822",
                resumable=False,
            )
            req = self._archive.insert(groupId=self._group_email, media_body=media)
            raw_data = req.execute(num_retries=0)
        except MediaUploadSizeError as exc:
            raise PermanentTransferError(
                f"Groups Migration upload exceeds maximum size: {exc}"
            ) from exc
        except HttpError as exc:
            raise translate_google_http_error(
                exc,
                service_name="Groups Migration",
                bad_request_cls=GroupsBadMessageError,
            ) from exc
        except (OSError, modern_httplib2.HttpLib2Error) as exc:
            raise TransientTransferError(f"Groups Migration transport error: {exc}") from exc

        data = dict(raw_data) if isinstance(raw_data, Mapping) else {}
        resp_code = str(data.get("responseCode", "SUCCESS"))
        if resp_code == "SUCCESS":
            return data
        if resp_code in {"INVALID_MESSAGE", "INVALID_HEADER"}:
            raise GroupsBadMessageError(f"Groups Migration responseCode={resp_code}")
        if resp_code in {"BACKEND_ERROR", "RATE_LIMIT_EXCEEDED"}:
            raise TransientTransferError(f"Groups Migration responseCode={resp_code}")
        raise PermanentTransferError(f"Groups Migration responseCode={resp_code}")
