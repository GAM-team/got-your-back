"""Unit tests for Gmail module: sanitizer, labels, Discovery client, source, and sink."""

from __future__ import annotations

import base64
import json
import threading
import time
from datetime import datetime
from typing import Any

import modern_httplib2
import pytest
from googleapiclient.errors import HttpError

from gyb.core import (
    ConfigurationError,
    Message,
    PermanentTransferError,
    Sink,
    Source,
    TransferStatus,
    TransientTransferError,
)
from gyb.modules.gmail import (
    GMAIL_MAX_MESSAGE_BYTES,
    GmailBadRequestError,
    GmailClient,
    GmailLabelManager,
    GmailNotFoundError,
    GmailSink,
    GmailSource,
    extract_http_error_reasons,
    parse_retry_after,
    sanitize_rfc822_message,
    transform_label_for_gmail,
)


class FakeResponse(dict[str, str]):
    def __init__(
        self,
        status: int = 200,
        version: int = 20,
        headers: dict[str, str] | None = None,
        reason: str = "OK",
    ) -> None:
        super().__init__({k.lower(): v for k, v in (headers or {}).items()})
        self["status"] = str(status)
        self.status = status
        self.version = version
        self.http_version = "HTTP/2" if version == 20 else "HTTP/1.1"
        self.reason = reason


class QueuedTransport:
    def __init__(self) -> None:
        self.queue: list[tuple[FakeResponse, bytes] | Exception] = []
        self.requests: list[tuple[str, str, bytes | None, dict[str, str]]] = []
        self.closed = False
        self.last_http_version: str | None = None
        self._lock = threading.Lock()

    def push_json(
        self,
        data: Any,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.queue.append(
            (FakeResponse(status=status, headers=headers), json.dumps(data).encode("utf-8"))
        )

    def push_raw(
        self,
        content: bytes,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
        reason: str = "OK",
    ) -> None:
        self.queue.append((FakeResponse(status=status, headers=headers, reason=reason), content))

    def request(
        self,
        uri: str,
        method: str = "GET",
        body: Any = None,
        headers: dict[str, str] | None = None,
        **_: Any,
    ) -> tuple[FakeResponse, bytes]:
        raw_body: bytes | None
        if body is not None and hasattr(body, "read"):
            raw_body = body.read()
        elif isinstance(body, str):
            raw_body = body.encode("utf-8")
        else:
            raw_body = body

        with self._lock:
            self.requests.append((method, uri, raw_body, dict(headers or {})))
            nxt = self.queue.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        resp, payload = nxt
        self.last_http_version = resp.http_version
        return resp, payload

    def close(self) -> None:
        self.closed = True


def test_sanitizer_hygiene_variants() -> None:
    clean = (
        b"Message-ID: <ok@example.com>\r\n"
        b"Date: Tue, 16 Apr 2019 12:00:00 +0000\r\n"
        b"From: Alice <alice@example.com>\r\n\r\n"
        b"\x00\xffbinary-body"
    )
    out_clean, changes = sanitize_rfc822_message(clean)
    assert out_clean == clean
    assert changes == ()

    dirty_lf = b"Message-ID: broken id\nDate: not-a-date\nFrom: Display Only <>\n\nBodyPayload"
    san1, chg1 = sanitize_rfc822_message(
        dirty_lf,
        fallback_date=datetime(2020, 1, 2, 3, 4, 5),
    )
    assert chg1 == ("Message-ID", "Date", "From")
    assert b"X-GYB-Orig-Msg-Id: broken id" in san1
    assert b"X-GYB-Orig-Msg-Date: not-a-date" in san1
    assert b"X-GYB-Orig-Msg-From: Display Only <>" in san1
    assert b"Display Only <gyb-restore@gyb-restore.local>" in san1
    assert san1.endswith(b"\r\n\r\nBodyPayload")

    hdr_only = b"Subject: No Sender Or Date Or MsgId"
    san2, chg2 = sanitize_rfc822_message(
        hdr_only,
        cleanup_from="God of Thunder <thor@avengers.com>",
    )
    assert set(chg2) == {"Message-ID", "Date", "From"}
    assert b"God of Thunder <thor@avengers.com>" in san2

    san3, _ = sanitize_rfc822_message(
        b"From: Thor Odinson <invalid>\r\n\r\nhi",
        cleanup_from="thor@avengers.com",
    )
    assert b"Thor Odinson <thor@avengers.com>" in san3

    san4, _ = sanitize_rfc822_message(b"Subject: x\r\n\r\nhi", cleanup_from="thor@avengers.com")
    assert b"From: thor@avengers.com" in san4
    san5, _ = sanitize_rfc822_message(b"Subject: x\r\n\r\nhi")
    assert b"From: gyb-restore@gyb-restore.local" in san5


def test_gmail_label_transformations_and_single_flight_locking() -> None:
    assert transform_label_for_gmail("   ") is None
    assert transform_label_for_gmail("inbox") == "INBOX"
    assert transform_label_for_gmail("CHAT") == "Chats_restored"
    assert transform_label_for_gmail("archive/2024") == "_archive/2024"
    assert transform_label_for_gmail("Work", label_prefix="archive") == "_archive/Work"
    assert transform_label_for_gmail("Work", label_prefix="Restored") == "Restored/Work"
    assert transform_label_for_gmail("Work", label_prefix=" / ") == "Work"

    tr = QueuedTransport()
    client = GmailClient(tr)  # type: ignore[arg-type]
    mgr = GmailLabelManager(client)

    tr.push_json({"labels": [{"id": "INBOX", "name": "INBOX"}, {"id": "L1", "name": "Existing"}]})
    mgr.refresh()
    assert mgr.resolve_id_to_name("L1") == "Existing"

    tr.push_json({"labels": [{"id": "L2", "name": "Fresh"}]})
    assert mgr.resolve_id_to_name("L2") == "Fresh"
    tr.push_json({"labels": []})
    assert mgr.resolve_id_to_name("UNKNOWN_ID") == "UNKNOWN_ID"

    # Concurrent single-flight creation across 6 threads -> only 1 create_label call!
    create_calls = 0
    barrier = threading.Barrier(6)

    def _slow_create(name: str) -> dict[str, Any]:
        nonlocal create_calls
        create_calls += 1
        time.sleep(0.03)
        return {"id": "L-CONC", "name": name}

    client.create_label = _slow_create  # type: ignore[method-assign]
    results: list[str] = []

    def _worker() -> None:
        barrier.wait(timeout=2.0)
        results.append(mgr.ensure_label_id("ConcurrentLabel"))

    threads = [threading.Thread(target=_worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=2.0)
    assert results == ["L-CONC"] * 6
    assert create_calls == 1
    assert mgr.ensure_label_id("ConcurrentLabel") == "L-CONC"


def test_gmail_label_manager_prepare_and_conflict_paths() -> None:
    tr = QueuedTransport()
    client = GmailClient(tr)  # type: ignore[arg-type]
    mgr = GmailLabelManager(client)
    tr.push_json({"labels": []})
    mgr.refresh()

    # 409 conflict for 'Parent', 400 'exists or conflicts' for 'Parent/Child', normal 'Audit'
    tr.push_raw(b"", status=409)
    tr.push_json({"labels": [{"id": "LP", "name": "Parent"}]})
    tr.push_json({"error": {"message": "Label name exists or conflicts"}}, status=400)
    tr.push_json(
        {
            "labels": [
                {"id": "LP", "name": "Parent"},
                {"id": "LC", "name": "Parent/Child"},
            ]
        }
    )
    tr.push_json({"id": "LA", "name": "Audit"})

    ids, is_draft = mgr.prepare_import_labels(
        ["INBOX", "DRAFT", "Parent/Child", "  ", "Parent/Child"],
        label_restored="Audit",
    )
    assert is_draft is True
    assert ids == ["INBOX", "LC", "LA"]

    ids_stripped, draft_stripped = mgr.prepare_import_labels(
        ["Parent/Child", "DRAFT", "INBOX"],
        strip_labels=True,
        label_restored="DRAFT",
    )
    assert draft_stripped is True
    assert ids_stripped == []

    # Non-conflict 400 on create_label propagates immediately
    tr.push_json({"error": {"message": "Invalid label name"}}, status=400)
    with pytest.raises(GmailBadRequestError, match="Invalid label name"):
        mgr.ensure_label_id("Bad//Name")

    # Unresolvable 409 raises RuntimeError
    tr.push_raw(b"", status=409)
    tr.push_json({"labels": []})
    with pytest.raises(RuntimeError, match="after conflict"):
        mgr.ensure_label_id("GhostLabel")


def test_gmail_client_discovery_resumable_and_errors() -> None:
    assert parse_retry_after("not-a-mapping") is None
    assert parse_retry_after({"X-Other": "1", "Retry-After": "2.5"}) == 2.5
    assert parse_retry_after({"X-Only": "1"}) is None
    assert parse_retry_after({"Retry-After": "-1"}) is None
    assert parse_retry_after({"Retry-After": "Wed, 21 Oct 2026"}) is None

    # extract_http_error_reasons edge cases (empty, plain text, JSON list, dict w/o error)
    assert extract_http_error_reasons(
        HttpError(FakeResponse(500, reason=""), b"")
    ) == ("Empty error response", [])
    assert extract_http_error_reasons(
        HttpError(FakeResponse(502), b"bad gateway text")
    ) == ("bad gateway text", [])
    assert extract_http_error_reasons(
        HttpError(FakeResponse(500, reason="Server Err"), b"[1, 2]")
    ) == ("Server Err", [])
    assert extract_http_error_reasons(
        HttpError(FakeResponse(500, reason="Fallback"), b'{"other": 1}')
    ) == ("Fallback", [])
    assert extract_http_error_reasons(
        HttpError(
            FakeResponse(403, reason="FallbackMsg"),
            b'{"error": {"errors": ["bad-item", {"other": 1}, {"reason": "quotaExceeded"}]}}',
        )
    ) == ("FallbackMsg", ["quotaExceeded"])

    tr = QueuedTransport()
    client = GmailClient(tr, user_id="user@example.com", resumable_threshold_bytes=64)  # type: ignore[arg-type]
    assert client.transport is tr
    assert client.service is not None

    tr.push_json({"emailAddress": "user@example.com"})
    assert client.get_profile()["emailAddress"] == "user@example.com"
    assert client.last_http_version == "HTTP/2"

    # Non-mapping responses degrade gracefully to {} / []
    tr.push_raw(b"[]")
    assert client.list_labels() == []

    # Pagination in list_messages
    tr.push_json({"messages": [{"id": "m1"}], "nextPageToken": "p2"})
    tr.push_json({"messages": [{"id": "m2"}]})
    assert list(client.list_messages(query="from:bob", include_spam_trash=True)) == ["m1", "m2"]
    tr.push_json({"messages": []})
    assert list(client.list_messages(query=None)) == []

    # Small upload (< 64 bytes) uses 1-RTT JSON base64url (safe on 8-bit ISO-8859-1 MIME bodies)
    tr.push_json({"id": "small-1"})
    assert client.import_message(b"Subject: hi\r\n\r\nCaf\xe9")["id"] == "small-1"
    assert "uploadType=" not in tr.requests[-1][1]
    assert "raw" in json.loads(tr.requests[-1][2])

    # Larger upload (>= 64 bytes) uses MediaIoBaseUpload resumable protocol (init POST + chunk PUT)
    large_payload = b"Subject: big\r\n\r\nCaf\xe9 " + (b"A" * 100)
    tr.push_raw(
        b"",
        status=200,
        headers={"location": "https://gmail.googleapis.com/upload/resumable-session-1"},
    )
    tr.push_json({"id": "resumable-1"})
    res_big = client.import_message(large_payload, label_ids=["INBOX"])
    assert res_big["id"] == "resumable-1"
    assert "uploadType=resumable" in tr.requests[-2][1]
    assert tr.requests[-1][0] == "PUT"
    assert tr.requests[-1][2] == large_payload

    # Minimal create_draft without labels or thread_id (< 64 bytes)
    tr.push_json({"id": "d0", "message": {"id": "md0"}})
    assert client.create_draft(b"Subject: x\r\n\r\ny")["id"] == "d0"

    # Discovery MediaUploadSizeError (> 35 MiB on drafts.create) -> PermanentTransferError
    huge_draft = b"x" * (36 * 1024 * 1024)
    with pytest.raises(PermanentTransferError, match="exceeds maximum size"):
        client.create_draft(huge_draft)

    # Delete message & label (empty 204 response)
    tr.push_raw(b"", status=204)
    client.delete_message("m1")
    tr.push_raw(b"", status=204)
    client.delete_label("L1")

    # Error mappings: HttpLib2Error, 429, 403 rateLimitExceeded, 403 permanent, 400, 404
    tr.queue.append(modern_httplib2.HttpLib2Error("h2 stream reset"))
    with pytest.raises(TransientTransferError, match="transport error"):
        client.get_profile()

    tr.push_json(
        {"error": {"message": "Too many", "errors": [{"reason": "rateLimitExceeded"}]}},
        status=429,
        headers={"Retry-After": "4"},
    )
    with pytest.raises(TransientTransferError) as exc429:
        client.get_profile()
    assert exc429.value.retry_after == 4.0

    tr.push_json(
        {"error": {"message": "User rate", "errors": [{"reason": "userRateLimitExceeded"}]}},
        status=403,
    )
    with pytest.raises(TransientTransferError, match="quota throttle"):
        client.get_profile()

    tr.push_json(
        {"error": {"message": "Forbidden", "errors": [{"reason": "insufficientPermissions"}]}},
        status=403,
    )
    with pytest.raises(PermanentTransferError, match="Gmail HTTP 403"):
        client.get_profile()

    tr.push_json({"error": {"message": "Invalid From"}}, status=400)
    with pytest.raises(GmailBadRequestError, match="400 Bad Request"):
        client.get_profile()

    tr.push_json({"error": {"message": "Requested entity was not found."}}, status=404)
    with pytest.raises(GmailNotFoundError, match="404 Not Found"):
        client.get_message("missing-id")


def test_gmail_source_and_sink_full_flows() -> None:
    tr = QueuedTransport()
    client = GmailClient(tr, user_id="me")  # type: ignore[arg-type]

    src = GmailSource(client, close_transport=False)
    assert isinstance(src, Source)
    assert bool(src.capabilities)
    assert src.client is client
    with pytest.raises(ConfigurationError):
        list(src.list_messages())
    with pytest.raises(ConfigurationError):
        src.fetch_message("m1")

    raw_msg = b"Message-ID: <1@a>\r\nDate: Tue, 16 Apr 2019 12:00:00 +0000\r\n\r\nHi"
    b64 = base64.urlsafe_b64encode(raw_msg).decode("ascii").rstrip("=")

    tr.push_json({"labels": [{"id": "INBOX", "name": "INBOX"}, {"id": "CHAT", "name": "CHAT"}]})
    with src:
        tr.push_json({"messages": [{"id": "m1"}]})
        assert list(src.list_messages(query="is:unread")) == ["m1"]
        tr.push_json({"messages": []})
        assert list(src.list_messages(query=None)) == []

        tr.push_json(
            {
                "id": "m1",
                "threadId": "th-1",
                "labelIds": ["INBOX", "CHAT"],
                "internalDate": "1555416000000",
                "raw": b64,
            }
        )
        fetched = src.fetch_message("m1")
        assert fetched.labels == ("INBOX",)
        assert fetched.thread_id == "th-1"
        assert fetched.raw_rfc822 == raw_msg

        tr.push_json({"id": "m2", "internalDate": "not-an-int", "raw": b64})
        assert src.fetch_message("m2").internal_date is not None
        tr.push_json({"id": "m2b", "raw": b64})
        assert src.fetch_message("m2b").internal_date is not None
        tr.push_json({"id": "m3"})
        with pytest.raises(PermanentTransferError, match="missing raw payload"):
            src.fetch_message("m3")
    assert not tr.closed

    src_close = GmailSource(client, close_transport=True)
    src_close.close()
    assert tr.closed
    tr.closed = False

    sink = GmailSink(client, preserve_threads=True, close_transport=True)
    assert isinstance(sink, Sink)
    assert bool(sink.capabilities)
    assert sink.client is client
    assert sink.label_manager is not None
    with pytest.raises(ConfigurationError):
        sink.import_message(fetched)

    tr.push_json({"labels": [{"id": "INBOX", "name": "INBOX"}]})
    with sink:
        oversize = Message(source_id="big", raw_rfc822=b"x" * (GMAIL_MAX_MESSAGE_BYTES + 1))
        with pytest.raises(PermanentTransferError, match="exceeds Gmail maximum"):
            sink.import_message(oversize)

        # Foreign threadId 404 Not Found -> falls back to thread_id=None and succeeds!
        tr.push_json({"error": {"message": "Requested entity was not found."}}, status=404)
        tr.push_json({"id": "imported-no-thread"})
        res_foreign = sink.import_message(fetched)
        assert res_foreign.status == TransferStatus.SUCCESS
        assert res_foreign.destination_id == "imported-no-thread"

        # Foreign threadId 400 Invalid thread_id value -> falls back to thread_id=None without
        # mutating headers!
        tr.push_json({"error": {"message": "Invalid thread_id value"}}, status=400)
        tr.push_json({"id": "imported-400-thread"})
        res_foreign_400 = sink.import_message(fetched)
        assert res_foreign_400.status == TransferStatus.SUCCESS
        assert res_foreign_400.destination_id == "imported-400-thread"
        assert res_foreign_400.sanitized is False

        # 404 when thread_id is None propagates GmailNotFoundError
        tr.push_json({"error": {"message": "Mailbox not found"}}, status=404)
        with pytest.raises(GmailNotFoundError):
            sink.import_message(fetched.with_updates(thread_id=None))

        # 400 on import -> sanitize -> 400 on import -> succeeds on insert fallback
        malformed = Message(
            source_id="bad-hdr",
            raw_rfc822=b"Subject: broken\r\n\r\nBody",
            labels=("INBOX",),
            thread_id="th-1",
        )
        tr.push_json({"error": {"message": "Invalid header"}}, status=400)
        tr.push_json({"error": {"message": "Invalid internal date"}}, status=400)
        tr.push_json({"id": "gmail-inserted-1"})
        res_fallback = sink.import_message(malformed)
        assert res_fallback.status == TransferStatus.SUCCESS
        assert res_fallback.destination_id == "gmail-inserted-1"
        assert res_fallback.sanitized is True

        # Draft upload with threadId & INBOX label (drafts.create + messages.modify)
        draft_msg = Message(
            source_id="d1",
            raw_rfc822=raw_msg,
            labels=("DRAFT", "INBOX"),
            thread_id="th-draft",
        )
        tr.push_json({"id": "draft-1", "message": {"id": "msg-draft-1"}})
        tr.push_json({"id": "msg-draft-1", "labelIds": ["DRAFT", "INBOX"]})
        res_draft = sink.import_message(draft_msg)
        assert res_draft.destination_id == "msg-draft-1"
        assert "/messages/msg-draft-1/modify" in tr.requests[-1][1]

        tr.push_json({"error": {"message": "Bad draft"}}, status=400)
        tr.push_json({"error": {"message": "Still bad"}}, status=400)
        with pytest.raises(GmailBadRequestError):
            sink.import_message(draft_msg)
    assert tr.closed

    tr2 = QueuedTransport()
    sink2 = GmailSink(
        GmailClient(tr2),  # type: ignore[arg-type]
        cleanup=True,
        use_insert=True,
        preserve_threads=False,
        close_transport=False,
    )
    assert bool(sink2.capabilities)
    tr2.push_json({"labels": []})
    with sink2:
        tr2.push_json({"id": "clean-1"})
        r2 = sink2.import_message(Message(source_id="c1", raw_rfc822=b"Subject: hi\r\n\r\nbody"))
        assert r2.sanitized is True

        # Already-valid message with cleanup=True -> sanitized=False, empty id -> None
        valid_msg = (
            b"Message-ID: <ok@a>\r\nDate: Tue, 16 Apr 2019 12:00:00 +0000\r\n"
            b"From: a@b.com\r\n\r\nbody"
        )
        tr2.push_json({})
        r_valid = sink2.import_message(Message(source_id="c2", raw_rfc822=valid_msg))
        assert r_valid.sanitized is False
        assert r_valid.destination_id is None

        # use_insert=True getting 400 twice propagates GmailBadRequestError
        tr2.push_json({"error": {"message": "Bad insert"}}, status=400)
        tr2.push_json({"error": {"message": "Still bad insert"}}, status=400)
        with pytest.raises(GmailBadRequestError):
            sink2.import_message(Message(source_id="c3", raw_rfc822=valid_msg))
    assert not tr2.closed
