"""Gmail API v1 client built on google-api-python-client over modern-httplib2 HTTP/2."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Iterator, Mapping, Sequence
from functools import partial
from io import BytesIO
from typing import Any

import modern_httplib2
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError, MediaUploadSizeError
from googleapiclient.http import MediaIoBaseUpload

from gyb.auth.transport import ModernAuthorizedHttp
from gyb.core.exceptions import PermanentTransferError, TransientTransferError

RESUMABLE_THRESHOLD_BYTES = 1_048_576
RESUMABLE_CHUNK_SIZE = 4 * 1024 * 1024

RETRYABLE_GOOGLE_REASONS: frozenset[str] = frozenset(
    {
        "userRateLimitExceeded",
        "rateLimitExceeded",
        "quotaExceeded",
        "backendError",
        "internalError",
    }
)


class GmailBadRequestError(PermanentTransferError):
    """Raised on HTTP 400 from Gmail API (candidates for RFC 822 sanitization)."""


class GmailNotFoundError(PermanentTransferError):
    """Raised on HTTP 404 from Gmail API (missing message or foreign threadId)."""


def parse_retry_after(headers: Mapping[str, Any] | Any) -> float | None:
    """Extract numeric Retry-After seconds from response headers when present."""
    if not isinstance(headers, Mapping):
        return None
    for k, v in headers.items():
        if str(k).lower() == "retry-after":
            try:
                val = float(str(v).strip())
                return val if val > 0 else None
            except ValueError:
                return None
    return None


def extract_http_error_reasons(error: HttpError) -> tuple[str, list[str]]:
    """Extract human-readable message and Google reason codes from an HttpError."""
    reasons: list[str] = []
    raw_content = getattr(error, "content", b"")
    parsed_msg: str | None = None
    if isinstance(raw_content, bytes) and raw_content:
        try:
            payload = json.loads(raw_content.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            parsed_msg = raw_content.decode("utf-8", errors="replace").strip()
        else:
            err_obj = payload.get("error") if isinstance(payload, Mapping) else None
            if isinstance(err_obj, Mapping):
                if err_obj.get("message"):
                    parsed_msg = str(err_obj["message"])
                for item in err_obj.get("errors", []):
                    if isinstance(item, Mapping) and "reason" in item:
                        reasons.append(str(item["reason"]))

    message = parsed_msg or str(getattr(error, "reason", "")).strip() or "Empty error response"
    return message, reasons


def translate_google_http_error(
    error: HttpError,
    *,
    service_name: str,
    bad_request_cls: type[PermanentTransferError] = PermanentTransferError,
    not_found_cls: type[PermanentTransferError] = PermanentTransferError,
) -> TransientTransferError | PermanentTransferError:
    """Translate a googleapiclient HttpError into a GYB transient or permanent error."""
    status = int(error.status_code)
    message, reasons = extract_http_error_reasons(error)
    retry_after = parse_retry_after(error.resp)

    if status in {429, 500, 502, 503, 504}:
        return TransientTransferError(
            f"{service_name} HTTP {status}: {message}",
            retry_after=retry_after,
        )
    if status == 403 and any(r in RETRYABLE_GOOGLE_REASONS for r in reasons):
        return TransientTransferError(
            f"{service_name} quota throttle (403 {','.join(reasons)}): {message}",
            retry_after=retry_after,
        )
    if status == 400:
        return bad_request_cls(f"{service_name} 400 Bad Request: {message}")
    if status == 404:
        return not_found_cls(f"{service_name} 404 Not Found: {message}")
    return PermanentTransferError(f"{service_name} HTTP {status}: {message}")


class GmailClient:
    """Google Discovery Gmail v1 wrapper multiplexed over modern-httplib2 HTTP/2."""

    def __init__(
        self,
        transport: ModernAuthorizedHttp,
        user_id: str = "me",
        *,
        service: Any | None = None,
        resumable_threshold_bytes: int = RESUMABLE_THRESHOLD_BYTES,
    ) -> None:
        self._transport = transport
        self._user_id = user_id
        self._resumable_threshold_bytes = resumable_threshold_bytes
        self._service = (
            service
            if service is not None
            else build("gmail", "v1", http=transport, cache_discovery=False)
        )
        self._users = self._service.users()
        self._messages = self._users.messages()
        self._labels = self._users.labels()
        self._drafts = self._users.drafts()

    @property
    def transport(self) -> ModernAuthorizedHttp:
        return self._transport

    @property
    def service(self) -> Any:
        return self._service

    @property
    def last_http_version(self) -> str | None:
        """HTTP protocol version negotiated on the most recent API response."""
        return self._transport.last_http_version

    def _prepare_upload(
        self,
        raw_rfc822: bytes,
        payload_dict: dict[str, Any],
    ) -> MediaIoBaseUpload | None:
        """Select 1-RTT JSON base64url (<1 MiB) or chunked resumable MediaIoBaseUpload (>=1 MiB).

        Using JSON ``raw`` for small messages avoids ``googleapiclient``'s
        ``MIMENonMultipart("message", "rfc822")`` ASCII generator bug on 8-bit MIME bodies
        while preserving 1-RTT HTTP/2 multiplexing; ``resumable=True`` streams raw binary
        chunks directly for larger messages.
        """
        if len(raw_rfc822) < self._resumable_threshold_bytes:
            payload_dict["raw"] = base64.urlsafe_b64encode(raw_rfc822).decode("ascii")
            return None
        return MediaIoBaseUpload(
            BytesIO(raw_rfc822),
            mimetype="message/rfc822",
            chunksize=RESUMABLE_CHUNK_SIZE,
            resumable=True,
        )

    def _execute(
        self,
        request_factory: Callable[[], Any],
        *,
        allow_409_none: bool = False,
    ) -> Any:
        try:
            return request_factory().execute(num_retries=0)
        except MediaUploadSizeError as exc:
            raise PermanentTransferError(f"Gmail upload exceeds maximum size: {exc}") from exc
        except HttpError as exc:
            if allow_409_none and int(exc.status_code) == 409:
                return None
            raise translate_google_http_error(
                exc,
                service_name="Gmail",
                bad_request_cls=GmailBadRequestError,
                not_found_cls=GmailNotFoundError,
            ) from exc
        except (OSError, modern_httplib2.HttpLib2Error) as exc:
            raise TransientTransferError(f"Gmail transport error: {exc}") from exc

    def get_profile(self) -> dict[str, Any]:
        """Fetch mailbox profile for connectivity/auth verification."""
        data = self._execute(lambda: self._users.getProfile(userId=self._user_id))
        return dict(data) if isinstance(data, Mapping) else {}

    def list_labels(self) -> list[dict[str, Any]]:
        """List all labels in the target mailbox."""
        data = self._execute(lambda: self._labels.list(userId=self._user_id))
        if not isinstance(data, Mapping):
            return []
        return list(data.get("labels", []))

    def create_label(self, name: str) -> dict[str, Any] | None:
        """Create a user label, returning None if another worker already created it (409)."""
        body = {
            "name": name,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
        }
        data = self._execute(
            lambda: self._labels.create(userId=self._user_id, body=body),
            allow_409_none=True,
        )
        return dict(data) if isinstance(data, Mapping) else None

    def delete_label(self, label_id: str) -> None:
        """Delete a user label by ID."""
        self._execute(lambda: self._labels.delete(userId=self._user_id, id=label_id))

    def list_messages(
        self,
        *,
        query: str | None = None,
        include_spam_trash: bool = False,
        max_results: int = 500,
    ) -> Iterator[str]:
        """Stream all matching message IDs across pages."""
        page_token: str | None = None
        while True:
            data = self._execute(
                partial(
                    self._messages.list,
                    userId=self._user_id,
                    q=query,
                    includeSpamTrash=include_spam_trash,
                    maxResults=max_results,
                    pageToken=page_token,
                )
            )
            mapping = data if isinstance(data, Mapping) else {}
            for item in mapping.get("messages", []):
                yield str(item["id"])
            next_tok = mapping.get("nextPageToken")
            if not next_tok:
                return
            page_token = str(next_tok)

    def get_message(self, message_id: str, *, fmt: str = "raw") -> dict[str, Any]:
        """Fetch a single Gmail message resource."""
        data = self._execute(
            lambda: self._messages.get(userId=self._user_id, id=message_id, format=fmt)
        )
        return dict(data) if isinstance(data, Mapping) else {}

    def import_message(
        self,
        raw_rfc822: bytes,
        *,
        label_ids: Sequence[str] = (),
        thread_id: str | None = None,
        never_mark_spam: bool = True,
        deleted: bool = False,
        use_insert: bool = False,
    ) -> dict[str, Any]:
        """Import (or insert) an RFC 822 message via MediaIoBaseUpload over HTTP/2."""
        metadata: dict[str, Any] = {}
        if label_ids:
            metadata["labelIds"] = list(label_ids)
        if thread_id:
            metadata["threadId"] = thread_id

        media = self._prepare_upload(raw_rfc822, metadata)
        if use_insert:
            data = self._execute(
                lambda: self._messages.insert(
                    userId=self._user_id,
                    body=metadata,
                    media_body=media,
                    internalDateSource="receivedTime",
                    deleted=deleted,
                )
            )
        else:
            data = self._execute(
                lambda: self._messages.import_(
                    userId=self._user_id,
                    body=metadata,
                    media_body=media,
                    internalDateSource="dateHeader",
                    neverMarkSpam=never_mark_spam,
                    deleted=deleted,
                )
            )
        return dict(data) if isinstance(data, Mapping) else {}

    def modify_message_labels(
        self,
        message_id: str,
        *,
        add_label_ids: Sequence[str] = (),
    ) -> dict[str, Any]:
        """Apply additional label IDs to an existing Gmail message."""
        data = self._execute(
            lambda: self._messages.modify(
                userId=self._user_id,
                id=message_id,
                body={"addLabelIds": list(add_label_ids)},
            )
        )
        return dict(data) if isinstance(data, Mapping) else {}

    def create_draft(
        self,
        raw_rfc822: bytes,
        *,
        label_ids: Sequence[str] = (),
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a Gmail draft message via MediaIoBaseUpload over HTTP/2.

        Gmail's ``drafts.create`` endpoint rejects ``labelIds`` in the initial upload
        payload (``400 Bad Request: Cannot set labels on drafts``), so any non-``DRAFT``
        labels are applied afterward via ``messages.modify`` on the draft's message ID.
        """
        msg_meta: dict[str, Any] = {}
        if thread_id:
            msg_meta["threadId"] = thread_id
        media = self._prepare_upload(raw_rfc822, msg_meta)
        data = self._execute(
            lambda: self._drafts.create(
                userId=self._user_id,
                body={"message": msg_meta},
                media_body=media,
            )
        )
        draft_resp = dict(data) if isinstance(data, Mapping) else {}

        extra_labels = [lid for lid in label_ids if lid != "DRAFT"]
        msg_obj = draft_resp.get("message")
        msg_id = msg_obj.get("id") if isinstance(msg_obj, Mapping) else None
        if extra_labels and msg_id:
            self.modify_message_labels(str(msg_id), add_label_ids=extra_labels)
        return draft_resp

    def delete_message(self, message_id: str) -> None:
        """Permanently delete a message by ID."""
        self._execute(lambda: self._messages.delete(userId=self._user_id, id=message_id))
