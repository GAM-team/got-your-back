"""Unit tests for Gmail module: sanitizer, labels, client, source, and sink."""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any

import pytest

from ngyb.core import (
    ConfigurationError,
    Message,
    PermanentTransferError,
    Sink,
    Source,
    TransferStatus,
    TransientTransferError,
)
from ngyb.modules.gmail import (
    GMAIL_MAX_MESSAGE_BYTES,
    GmailBadRequestError,
    GmailClient,
    GmailLabelManager,
    GmailSink,
    GmailSource,
    parse_google_api_error,
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
    ) -> None:
        super().__init__(headers or {})
        self.status = status
        self.version = version


class QueuedTransport:
    def __init__(self) -> None:
        self.queue: list[tuple[FakeResponse, bytes] | Exception] = []
        self.requests: list[tuple[str, str, bytes | None, dict[str, str]]] = []
        self.closed = False

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
    ) -> None:
        self.queue.append((FakeResponse(status=status, headers=headers), content))

    def request(
        self,
        uri: str,
        method: str = "GET",
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        **_: Any,
    ) -> tuple[FakeResponse, bytes]:
        self.requests.append((method, uri, body, dict(headers or {})))
        nxt = self.queue.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    def close(self) -> None:
        self.closed = True


def test_sanitizer_hygiene_variants() -> None:
    # Clean message passes through byte-for-byte untouched
    clean = (
        b"Message-ID: <ok@example.com>\r\n"
        b"Date: Tue, 16 Apr 2019 12:00:00 +0000\r\n"
        b"From: Alice <alice@example.com>\r\n\r\n"
        b"\x00\xffbinary-body"
    )
    out_clean, changes = sanitize_rfc822_message(clean)
    assert out_clean == clean
    assert changes == ()

    # Malformed Message-ID, Date, and From (with display name) over LF-only message
    dirty_lf = b"Message-ID: broken id\nDate: not-a-date\nFrom: Display Only <>\n\nBodyPayload"
    san1, chg1 = sanitize_rfc822_message(
        dirty_lf,
        fallback_date=datetime(2020, 1, 2, 3, 4, 5),  # naive datetime branch
    )
    assert chg1 == ("Message-ID", "Date", "From")
    assert b"X-GYB-Orig-Msg-Id: broken id" in san1
    assert b"X-GYB-Orig-Msg-Date: not-a-date" in san1
    assert b"X-GYB-Orig-Msg-From: Display Only <>" in san1
    assert b"Display Only <gyb-restore@gyb-restore.local>" in san1
    assert san1.endswith(b"\r\n\r\nBodyPayload")

    # Header-only message (no body separator) + missing headers + cleanup_from variants
    hdr_only = b"Subject: No Sender Or Date Or MsgId"
    san2, chg2 = sanitize_rfc822_message(
        hdr_only,
        cleanup_from="God of Thunder <thor@avengers.com>",
    )
    assert set(chg2) == {"Message-ID", "Date", "From"}
    assert b"God of Thunder <thor@avengers.com>" in san2

    # cleanup_from plain email + existing display name
    san3, _ = sanitize_rfc822_message(
        b"From: Thor Odinson <invalid>\r\n\r\nhi",
        cleanup_from="thor@avengers.com",
    )
    assert b"Thor Odinson <thor@avengers.com>" in san3

    # cleanup_from plain email without display name & default fallback without display name
    san4, _ = sanitize_rfc822_message(b"Subject: x\r\n\r\nhi", cleanup_from="thor@avengers.com")
    assert b"From: thor@avengers.com" in san4
    san5, _ = sanitize_rfc822_message(b"Subject: x\r\n\r\nhi")
    assert b"From: gyb-restore@gyb-restore.local" in san5


def test_gmail_label_transformations_and_conflict_resolution() -> None:
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

    # Initial refresh
    tr.push_json({"labels": [{"id": "INBOX", "name": "INBOX"}, {"id": "L1", "name": "Existing"}]})
    mgr.refresh()
    assert mgr.resolve_id_to_name("L1") == "Existing"

    # Unknown label ID triggers refresh fallback
    tr.push_json({"labels": [{"id": "L2", "name": "Fresh"}]})
    assert mgr.resolve_id_to_name("L2") == "Fresh"
    tr.push_json({"labels": []})
    assert mgr.resolve_id_to_name("UNKNOWN_ID") == "UNKNOWN_ID"


def test_gmail_label_manager_prepare_and_409_unresolvable() -> None:
    tr = QueuedTransport()
    client = GmailClient(tr)  # type: ignore[arg-type]
    mgr = GmailLabelManager(client)
    tr.push_json({"labels": []})
    mgr.refresh()

    # 409 conflict for 'Parent' -> refresh returns 'Parent'; then create 'Parent/Child' + 'Audit'
    tr.push_raw(b"", status=409)
    tr.push_json({"labels": [{"id": "LP", "name": "Parent"}]})
    tr.push_json({"id": "LC", "name": "Parent/Child"})
    tr.push_json({"id": "LA", "name": "Audit"})

    ids, is_draft = mgr.prepare_import_labels(
        ["INBOX", "DRAFT", "Parent/Child", "  ", "Parent/Child"],
        label_restored="Audit",
    )
    assert is_draft is True
    assert ids == ["INBOX", "LC", "LA"]

    # strip_labels=True still preserves DRAFT status and label_restored
    ids_stripped, draft_stripped = mgr.prepare_import_labels(
        ["Parent/Child", "DRAFT", "INBOX"],
        strip_labels=True,
        label_restored="DRAFT",  # DRAFT in label_restored is ignored as labelId
    )
    assert draft_stripped is True
    assert ids_stripped == []

    # Unresolvable 409 raises RuntimeError
    tr.push_raw(b"", status=409)
    tr.push_json({"labels": []})
    with pytest.raises(RuntimeError, match="after 409 Conflict"):
        mgr.ensure_label_id("GhostLabel")


def test_gmail_client_errors_and_endpoints() -> None:
    assert parse_retry_after("not-a-mapping") is None
    assert parse_retry_after({"X-Other": "1", "Retry-After": "2.5"}) == 2.5
    assert parse_retry_after({"X-Only": "1"}) is None
    assert parse_retry_after({"Retry-After": "-1"}) is None
    assert parse_retry_after({"Retry-After": "Wed, 21 Oct 2026"}) is None
    assert parse_google_api_error(b"") == ("Empty error response", [])
    assert parse_google_api_error(b"plain text error") == ("plain text error", [])
    assert parse_google_api_error(b"[1, 2]") == ("[1, 2]", [])
    assert parse_google_api_error(b'{"other": 1}') == ("{'other': 1}", [])

    tr = QueuedTransport()
    client = GmailClient(tr, user_id="user@example.com")  # type: ignore[arg-type]
    assert client.transport is tr

    tr.push_json({"emailAddress": "user@example.com"})
    assert client.get_profile()["emailAddress"] == "user@example.com"
    assert client.last_http_version == 20

    # Pagination in list_messages (with and without query)
    tr.push_json({"messages": [{"id": "m1"}], "nextPageToken": "p2"})
    tr.push_json({"messages": [{"id": "m2"}]})
    assert list(client.list_messages(query="from:bob", include_spam_trash=True)) == ["m1", "m2"]
    tr.push_json({"messages": []})
    assert list(client.list_messages(query=None)) == []

    # Minimal create_draft without labels or thread_id
    tr.push_json({"id": "d0", "message": {"id": "md0"}})
    assert client.create_draft(b"Subject: x\r\n\r\ny")["id"] == "d0"

    # Delete message & label (empty 204 response)
    tr.push_raw(b"", status=204)
    client.delete_message("m1")
    tr.push_raw(b"", status=204)
    client.delete_label("L1")

    # Error mappings: OSError, 429, 403 rateLimitExceeded, 403 permanent, 400
    tr.queue.append(OSError("connection reset"))
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


def test_gmail_source_and_sink_full_flows() -> None:
    tr = QueuedTransport()
    client = GmailClient(tr, user_id="me")  # type: ignore[arg-type]

    # Source disconnected checks
    src = GmailSource(client, close_transport=False)
    assert isinstance(src, Source)
    assert bool(src.capabilities)
    assert src.client is client
    with pytest.raises(ConfigurationError):
        list(src.list_messages())
    with pytest.raises(ConfigurationError):
        src.fetch_message("m1")

    tr.push_json({"labels": [{"id": "INBOX", "name": "INBOX"}, {"id": "CHAT", "name": "CHAT"}]})
    src.connect()
    tr.push_json({"messages": [{"id": "m1"}]})
    assert list(src.list_messages(query="is:unread")) == ["m1"]
    tr.push_json({"messages": []})
    assert list(src.list_messages(query=None)) == []

    raw_msg = b"Message-ID: <1@a>\r\nDate: Tue, 16 Apr 2019 12:00:00 +0000\r\n\r\nHi"
    b64 = base64.urlsafe_b64encode(raw_msg).decode("ascii").rstrip("=")
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

    # Invalid internalDate & omitted internalDate fall back to Date header; missing raw raises
    tr.push_json({"id": "m2", "internalDate": "not-an-int", "raw": b64})
    assert src.fetch_message("m2").internal_date is not None
    tr.push_json({"id": "m2b", "raw": b64})
    assert src.fetch_message("m2b").internal_date is not None
    tr.push_json({"id": "m3"})
    with pytest.raises(PermanentTransferError, match="missing raw payload"):
        src.fetch_message("m3")
    src.close()
    assert not tr.closed

    src_close = GmailSource(client, close_transport=True)
    src_close.close()
    assert tr.closed
    tr.closed = False

    # Sink tests: disconnected, oversize, proactive cleanup, 400 -> sanitize -> insert, draft
    sink = GmailSink(client, preserve_threads=True, close_transport=True)
    assert isinstance(sink, Sink)
    assert bool(sink.capabilities)
    assert sink.client is client
    assert sink.label_manager is not None
    with pytest.raises(ConfigurationError):
        sink.import_message(fetched)

    tr.push_json({"labels": [{"id": "INBOX", "name": "INBOX"}]})
    sink.connect()

    oversize = Message(source_id="big", raw_rfc822=b"x" * (GMAIL_MAX_MESSAGE_BYTES + 1))
    with pytest.raises(PermanentTransferError, match="exceeds Gmail maximum"):
        sink.import_message(oversize)

    # 400 on import -> sanitize -> 400 on import -> succeeds on insert fallback!
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

    # Draft upload with threadId & user label (drafts.create + messages.modify)
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
    assert tr.requests[-1][1].endswith("/messages/msg-draft-1/modify")

    # Draft that fails twice with 400 raises GmailBadRequestError
    tr.push_json({"error": {"message": "Bad draft"}}, status=400)
    tr.push_json({"error": {"message": "Still bad"}}, status=400)
    with pytest.raises(GmailBadRequestError):
        sink.import_message(draft_msg)

    sink.close()
    assert tr.closed

    # Proactive cleanup=True + close_transport=False
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
    sink2.connect()
    tr2.push_json({"id": "clean-1"})
    r2 = sink2.import_message(Message(source_id="c1", raw_rfc822=b"Subject: hi\r\n\r\nbody"))
    assert r2.sanitized is True
    sink2.close()
    assert not tr2.closed
