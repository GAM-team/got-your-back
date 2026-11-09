"""Thread-safe HTTP/2 multiplexed transport backed by modern-httplib2."""

from __future__ import annotations

import math
import threading
from collections.abc import Callable, Mapping
from typing import Any

import google.auth.credentials
import google.auth.exceptions
import google_auth_httplib2
import modern_httplib2
import modern_httplib2.auto  # noqa: F401

from ngyb.core.exceptions import AuthenticationError


def compute_pool_maxsize(max_streams: int) -> int:
    """Compute modern-httplib2 connection pool size for concurrent HTTP/2 streams."""
    return max(16, math.ceil(max(1, max_streams) / 90) * 2)


class ModernAuthorizedHttp:
    """Thread-safe authorized HTTP/2 client multiplexing concurrent streams.

    - Uses ``modern_httplib2.Http`` with HTTP/2 enabled by default and automatic
      HTTP/1.1 downgrade fallback.
    - Serializes token refresh requests across worker threads with a lock so
      concurrent HTTP/2 streams never race on DPoP nonces or refresh tokens.
    - Attaches per-request ``Authorization`` and ``DPoP`` proof headers via
      ``credentials.before_request(...)``.
    """

    def __init__(
        self,
        credentials: google.auth.credentials.Credentials,
        *,
        max_streams: int = 64,
        enable_http2: bool = True,
        timeout: float = 60.0,
        http: Any | None = None,
        refresh_http: Any | None = None,
        on_credentials_refreshed: Callable[[google.auth.credentials.Credentials], None]
        | None = None,
    ) -> None:
        self._credentials = credentials
        self._refresh_lock = threading.Lock()
        self._on_refreshed = on_credentials_refreshed

        pool_size = compute_pool_maxsize(max_streams)
        self._http = (
            http
            if http is not None
            else modern_httplib2.Http(
                timeout=timeout,
                enable_http2=enable_http2,
                auto_downgrade_http2=True,
                pool_maxsize=pool_size,
            )
        )
        self._refresh_http = (
            refresh_http
            if refresh_http is not None
            else modern_httplib2.Http(
                timeout=timeout,
                enable_http2=enable_http2,
                auto_downgrade_http2=True,
                pool_maxsize=4,
            )
        )
        self._auth_request = google_auth_httplib2.Request(self._refresh_http)

    @property
    def credentials(self) -> google.auth.credentials.Credentials:
        """Bound google-auth credentials."""
        return self._credentials

    @property
    def http(self) -> Any:
        """Underlying modern_httplib2.Http pool."""
        return self._http

    @property
    def auth_request(self) -> Any:
        """google-auth transport Request used for token refreshes."""
        return self._auth_request

    def ensure_valid_token(self, *, force: bool = False) -> None:
        """Refresh credentials under a single-flight lock when expired or forced."""
        with self._refresh_lock:
            if force or not self._credentials.valid:
                try:
                    self._credentials.refresh(self._auth_request)
                except google.auth.exceptions.GoogleAuthError as exc:
                    raise AuthenticationError(f"Credential refresh failed: {exc}") from exc
                if self._on_refreshed is not None:
                    self._on_refreshed(self._credentials)

    def request(
        self,
        uri: str,
        method: str = "GET",
        body: bytes | str | None = None,
        headers: Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> tuple[Any, bytes]:
        """Execute an authenticated HTTP/2 request with automatic 401 token refresh."""
        self.ensure_valid_token(force=False)
        req_headers = dict(headers) if headers is not None else {}
        self._credentials.before_request(self._auth_request, method, uri, req_headers)

        response, content = self._http.request(
            uri,
            method=method,
            body=body,
            headers=req_headers,
            **kwargs,
        )
        if int(getattr(response, "status", 200)) == 401:
            self.ensure_valid_token(force=True)
            retry_headers = dict(headers) if headers is not None else {}
            self._credentials.before_request(self._auth_request, method, uri, retry_headers)
            response, content = self._http.request(
                uri,
                method=method,
                body=body,
                headers=retry_headers,
                **kwargs,
            )
        raw_bytes = content if isinstance(content, bytes) else str(content).encode("utf-8")
        return response, raw_bytes

    def close(self) -> None:
        """Close underlying modern-httplib2 connection pools."""
        self._http.close()
        self._refresh_http.close()
