"""Unit tests for GoogleGroupsSink and GroupsMigrationClient."""

from __future__ import annotations

import pytest
from tests.unit.test_module_gmail import QueuedTransport

from ngyb.core import (
    ConfigurationError,
    Message,
    PermanentTransferError,
    Sink,
    TransferStatus,
    TransientTransferError,
)
from ngyb.modules.google_groups import (
    GROUPS_MAX_MESSAGE_BYTES,
    GoogleGroupsSink,
    GroupsBadMessageError,
    GroupsMigrationClient,
)


def test_groups_migration_client_and_sink() -> None:
    tr = QueuedTransport()
    client = GroupsMigrationClient(tr, "team@example.com")  # type: ignore[arg-type]
    assert client.transport is tr
    assert client.group_email == "team@example.com"

    # Transport error, 429, 400, 403 permanent, and responseCode branches
    tr.queue.append(OSError("socket closed"))
    with pytest.raises(TransientTransferError, match="transport error"):
        client.insert_archive_message(b"raw")

    tr.push_json({"error": {"message": "Throttle"}}, status=429)
    with pytest.raises(TransientTransferError, match="HTTP 429"):
        client.insert_archive_message(b"raw")
    assert client.last_http_version == 20

    tr.push_json({"error": {"message": "Forbidden"}}, status=403)
    with pytest.raises(PermanentTransferError, match="HTTP 403"):
        client.insert_archive_message(b"raw")

    tr.push_json({"error": {"message": "Bad RFC822"}}, status=400)
    with pytest.raises(GroupsBadMessageError):
        client.insert_archive_message(b"raw")

    tr.push_json({"responseCode": "RATE_LIMIT_EXCEEDED"})
    with pytest.raises(TransientTransferError, match="RATE_LIMIT_EXCEEDED"):
        client.insert_archive_message(b"raw")

    tr.push_json({"responseCode": "MESSAGE_TOO_LARGE"})
    with pytest.raises(PermanentTransferError, match="MESSAGE_TOO_LARGE"):
        client.insert_archive_message(b"raw")

    # Sink tests
    sink = GoogleGroupsSink(client, close_transport=True)
    assert isinstance(sink, Sink)
    assert bool(sink.capabilities)
    assert sink.client is client
    with pytest.raises(ConfigurationError):
        sink.import_message(Message(source_id="1", raw_rfc822=b"x"))

    sink.connect()
    with pytest.raises(PermanentTransferError, match="exceeds Google Groups maximum"):
        sink.import_message(
            Message(source_id="big", raw_rfc822=b"x" * (GROUPS_MAX_MESSAGE_BYTES + 1))
        )

    # INVALID_MESSAGE -> auto-sanitize -> SUCCESS
    tr.push_json({"responseCode": "INVALID_MESSAGE"})
    tr.push_json({"responseCode": "SUCCESS"})
    res = sink.import_message(Message(source_id="g1", raw_rfc822=b"Subject: no-from\r\n\r\nhi"))
    assert res.status == TransferStatus.SUCCESS
    assert res.sanitized is True
    assert res.destination_id == "team@example.com"

    # Already-valid headers failing with GroupsBadMessageError re-raises without loop
    valid_raw = (
        b"Message-ID: <ok@example.com>\r\n"
        b"Date: Tue, 16 Apr 2019 12:00:00 +0000\r\n"
        b"From: Alice <alice@example.com>\r\n\r\nhi"
    )
    tr.push_json({"responseCode": "INVALID_MESSAGE"})
    with pytest.raises(GroupsBadMessageError):
        sink.import_message(Message(source_id="g2", raw_rfc822=valid_raw))

    sink.close()
    assert tr.closed

    # Proactive cleanup=True + close_transport=False
    tr2 = QueuedTransport()
    sink2 = GoogleGroupsSink(
        GroupsMigrationClient(tr2, "team@example.com"),  # type: ignore[arg-type]
        cleanup=True,
        cleanup_from="archive@example.com",
        close_transport=False,
    )
    sink2.connect()
    tr2.push_raw(b"")  # empty 200 defaults to SUCCESS
    r2 = sink2.import_message(Message(source_id="g3", raw_rfc822=b"Subject: test\r\n\r\nhi"))
    assert r2.sanitized is True
    sink2.close()
    assert not tr2.closed
