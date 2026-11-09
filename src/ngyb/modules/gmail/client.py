"""Gmail REST v1 client multiplexed over modern-httplib2 HTTP/2 streams."""

from __future__ import annotations

import json
import urllib.parse
import uuid
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

from ngyb.auth.transport import ModernAuthorizedHttp
from ngyb.core.exceptions import PermanentTransferError, TransientTransferError

GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
GMAIL_UPLOAD_BASE = "https://gmail.googleapis.com/upload/gmail/v1"

RETRYABLE_GMAIL_REASONS: frozenset[str] = frozenset(
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


def parse_google_api_error(content: bytes) -> tuple[str, list[str]]:
    """Extract error message and reason codes from a Google JSON error payload."""
    if not content:
        return "Empty error response", []
    try:
        payload = json.loads(content.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return content.decode("utf-8", errors="replace").strip(), []

    if not isinstance(payload, Mapping):
        return str(payload), []
    err = payload.get("error")
    if isinstance(err, Mapping):
        msg = str(err.get("message") or payload)
        reasons = [
            str(item["reason"])
            for item in err.get("errors", [])
            if isinstance(item, Mapping) and "reason" in item
        ]
        return msg, reasons
    return str(payload), []


def build_multipart_related(metadata: Mapping[str, Any], raw_rfc822: bytes) -> tuple[str, bytes]:
    """Construct an RFC 2387 multipart/related upload body without base64 bloat."""
    boundary = f"===============ngyb_{uuid.uuid4().hex}=="
    meta_json = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    body = (f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n").encode(
        "ascii"
    )
    body += meta_json
    body += (f"\r\n--{boundary}\r\nContent-Type: message/rfc822\r\n\r\n").encode("ascii")
    body += raw_rfc822
    body += f"\r\n--{boundary}--\r\n".encode("ascii")
    content_type = f'multipart/related; boundary="{boundary}"'
    return content_type, body


class GmailClient:
    """Low-level HTTP/2 Gmail API wrapper translating Gmail errors to core exceptions."""

    def __init__(self, transport: ModernAuthorizedHttp, user_id: str = "me") -> None:
        self._transport = transport
        self._user_id = urllib.parse.quote(user_id, safe="@.")
        self._last_http_version: int | None = None

    @property
    def transport(self) -> ModernAuthorizedHttp:
        return self._transport

    @property
    def last_http_version(self) -> int | None:
        """HTTP protocol version of the most recent response (20 for HTTP/2, 11 for HTTP/1.1)."""
        return self._last_http_version

    def _raise_for_error(self, status: int, response: Any, content: bytes) -> None:
        message, reasons = parse_google_api_error(content)
        retry_after = parse_retry_after(response)

        if status in {429, 500, 502, 503, 504}:
            raise TransientTransferError(
                f"Gmail HTTP {status}: {message}",
                retry_after=retry_after,
            )
        if status == 403 and any(r in RETRYABLE_GMAIL_REASONS for r in reasons):
            raise TransientTransferError(
                f"Gmail quota throttle (403 {','.join(reasons)}): {message}",
                retry_after=retry_after,
            )
        if status == 400:
            raise GmailBadRequestError(f"Gmail 400 Bad Request: {message}")
        raise PermanentTransferError(f"Gmail HTTP {status}: {message}")

    def _request_json(
        self,
        url: str,
        *,
        method: str = "GET",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        allow_409_none: bool = False,
        allow_empty_response: bool = False,
    ) -> dict[str, Any] | None:
        try:
            response, content = self._transport.request(
                url,
                method=method,
                body=body,
                headers=headers,
            )
        except OSError as exc:
            raise TransientTransferError(f"Gmail transport error: {exc}") from exc

        self._last_http_version = getattr(response, "version", None)
        status = int(getattr(response, "status", 200))
        if allow_409_none and status == 409:
            return None
        if status >= 400:
            self._raise_for_error(status, response, content)
        if allow_empty_response and not content:
            return {}
        return dict(json.loads(content.decode("utf-8")))

    def get_profile(self) -> dict[str, Any]:
        """Fetch mailbox profile for connectivity/auth verification."""
        url = f"{GMAIL_API_BASE}/users/{self._user_id}/profile"
        data = self._request_json(url)
        return data or {}

    def list_labels(self) -> list[dict[str, Any]]:
        """List all labels in the target mailbox."""
        url = f"{GMAIL_API_BASE}/users/{self._user_id}/labels"
        data = self._request_json(url) or {}
        return list(data.get("labels", []))

    def create_label(self, name: str) -> dict[str, Any] | None:
        """Create a user label, returning None if another worker already created it (409)."""
        url = f"{GMAIL_API_BASE}/users/{self._user_id}/labels"
        payload = json.dumps(
            {
                "name": name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            }
        ).encode("utf-8")
        return self._request_json(
            url,
            method="POST",
            body=payload,
            headers={"Content-Type": "application/json; charset=UTF-8"},
            allow_409_none=True,
        )

    def delete_label(self, label_id: str) -> None:
        """Delete a user label by ID."""
        encoded = urllib.parse.quote(label_id, safe="")
        url = f"{GMAIL_API_BASE}/users/{self._user_id}/labels/{encoded}"
        self._request_json(url, method="DELETE", allow_empty_response=True)

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
            params: dict[str, str] = {
                "maxResults": str(max_results),
                "includeSpamTrash": "true" if include_spam_trash else "false",
            }
            if query:
                params["q"] = query
            if page_token:
                params["pageToken"] = page_token
            qs = urllib.parse.urlencode(params)
            url = f"{GMAIL_API_BASE}/users/{self._user_id}/messages?{qs}"
            data = self._request_json(url) or {}
            for item in data.get("messages", []):
                yield str(item["id"])
            next_tok = data.get("nextPageToken")
            if not next_tok:
                return
            page_token = str(next_tok)

    def get_message(self, message_id: str, *, fmt: str = "raw") -> dict[str, Any]:
        """Fetch a single Gmail message resource."""
        encoded_id = urllib.parse.quote(message_id, safe="")
        qs = urllib.parse.urlencode({"format": fmt})
        url = f"{GMAIL_API_BASE}/users/{self._user_id}/messages/{encoded_id}?{qs}"
        return self._request_json(url) or {}

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
        """Import (or insert) an RFC 822 message via HTTP/2 multipart/related upload."""
        metadata: dict[str, Any] = {}
        if label_ids:
            metadata["labelIds"] = list(label_ids)
        if thread_id:
            metadata["threadId"] = thread_id

        content_type, body = build_multipart_related(metadata, raw_rfc822)
        if use_insert:
            params = {
                "uploadType": "multipart",
                "internalDateSource": "receivedTime",
                "deleted": "true" if deleted else "false",
            }
            endpoint = "insert"
        else:
            params = {
                "uploadType": "multipart",
                "internalDateSource": "dateHeader",
                "neverMarkSpam": "true" if never_mark_spam else "false",
                "deleted": "true" if deleted else "false",
            }
            endpoint = "import"

        qs = urllib.parse.urlencode(params)
        url = f"{GMAIL_UPLOAD_BASE}/users/{self._user_id}/messages/{endpoint}?{qs}"
        return (
            self._request_json(
                url,
                method="POST",
                body=body,
                headers={"Content-Type": content_type},
            )
            or {}
        )

    def create_draft(
        self,
        raw_rfc822: bytes,
        *,
        label_ids: Sequence[str] = (),
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a Gmail draft message via HTTP/2 multipart/related upload."""
        msg_meta: dict[str, Any] = {}
        if label_ids:
            msg_meta["labelIds"] = list(label_ids)
        if thread_id:
            msg_meta["threadId"] = thread_id
        content_type, body = build_multipart_related({"message": msg_meta}, raw_rfc822)
        url = f"{GMAIL_UPLOAD_BASE}/users/{self._user_id}/drafts?uploadType=multipart"
        return (
            self._request_json(
                url,
                method="POST",
                body=body,
                headers={"Content-Type": content_type},
            )
            or {}
        )

    def delete_message(self, message_id: str) -> None:
        """Permanently delete a message by ID."""
        encoded_id = urllib.parse.quote(message_id, safe="")
        url = f"{GMAIL_API_BASE}/users/{self._user_id}/messages/{encoded_id}"
        self._request_json(url, method="DELETE", allow_empty_response=True)
