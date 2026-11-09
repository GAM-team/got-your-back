"""Unit tests for LocalGYBSource and LocalGYBSink (including real samples/gyb-format)."""

from __future__ import annotations

import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ngyb.core import (
    ConfigurationError,
    Message,
    PermanentTransferError,
    Sink,
    Source,
    TransferStatus,
)
from ngyb.modules.local import (
    MSG_DB_FILENAME,
    LocalGYBSink,
    LocalGYBSource,
    sanitize_uid_for_filename,
)
from ngyb.modules.local.schema import format_gyb_timestamp, parse_gyb_timestamp

REPO_SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def test_real_gyb_format_sample_archive() -> None:
    sample_dir = REPO_SAMPLES / "gyb-format"
    src = LocalGYBSource(sample_dir)
    assert isinstance(src, Source)
    assert bool(src.capabilities)
    assert src.folder == sample_dir.resolve()
    src.connect()
    try:
        uids = list(src.list_messages())
        assert len(uids) == 11
        assert "16a281f4eb2462ec" in uids
        msg = src.fetch_message("16a281f4eb2462ec")
        assert msg.size_bytes > 1000
        assert "top/nested" in msg.labels
        assert "INBOX" in msg.labels
        assert msg.internal_date is not None

        # Verify fractional timestamp row (baddate) parses cleanly
        baddate_uid = uids[-1]
        bad_msg = src.fetch_message(baddate_uid)
        assert bad_msg.internal_date is not None
    finally:
        src.close()
        # Idempotent close
        src.close()


def test_local_sink_and_source_round_trip_and_schema_migration(tmp_path: Path) -> None:
    assert sanitize_uid_for_filename("  ../weird:id/1  ") == "weird_id_1"
    assert sanitize_uid_for_filename("...") == "message"
    assert parse_gyb_timestamp(None) is None
    assert parse_gyb_timestamp("   ") is None
    assert parse_gyb_timestamp("not-a-timestamp") is None
    assert parse_gyb_timestamp("2024-05-01T12:00:00+02:00") is not None

    # Pre-1970 timestamp clamping for Windows safety
    ts_str, clamped = format_gyb_timestamp(datetime(1970, 1, 1, 0, 0, 1))
    assert ts_str.startswith("1970-01-02")
    assert clamped.tzinfo == UTC
    # None timestamp defaults to now
    now_str, _ = format_gyb_timestamp(None)
    assert len(now_str) == 19

    archive = tmp_path / "backup"
    sink = LocalGYBSink(archive, email_address="user@example.com")
    assert isinstance(sink, Sink)
    assert bool(sink.capabilities)
    assert sink.folder == archive.resolve()
    assert sink.existing_uids() == set()

    with pytest.raises(ConfigurationError, match="not connected"):
        sink.import_message(Message(source_id="x", raw_rfc822=b""))

    sink.connect()
    try:
        m1 = Message(
            source_id="uid-1",
            raw_rfc822=(
                b"Message-ID: <m1@example.com>\r\n"
                b"Date: Tue, 16 Apr 2019 17:48:21 +0000\r\n\r\nHello"
            ),
            labels=("INBOX", "DRAFT", "INBOX"),
        )
        r1 = sink.import_message(m1)
        assert r1.status == TransferStatus.SUCCESS
        assert r1.destination_id == "2019/4/16/uid-1.eml"
        assert sink.existing_uids() == {"uid-1"}

        # Duplicate import updates labels and returns SKIPPED
        r1_dup = sink.import_message(m1.with_updates(labels=("STARRED",)))
        assert r1_dup.status == TransferStatus.SKIPPED

        # Message with corrupt Date header and naive internal_date=None
        m2 = Message(
            source_id="uid-2",
            raw_rfc822=b"Date: totally-invalid-date\r\nSubject: test\r\n\r\nBody",
            internal_date=datetime(2025, 1, 5, 8, 30, 0, tzinfo=UTC),
        )
        assert sink.import_message(m2).status == TransferStatus.SUCCESS
    finally:
        sink.close()
        sink.close()

    # existing_uids() when disconnected opens read-only DB cleanly
    assert sink.existing_uids() == {"uid-1", "uid-2"}

    # Read back with LocalGYBSource (has rfc822_msgid column)
    src = LocalGYBSource(archive)
    with pytest.raises(ConfigurationError, match="not connected"):
        list(src.list_messages())
    with pytest.raises(ConfigurationError, match="not connected"):
        src.fetch_message("uid-1")

    src.connect()
    try:
        assert list(src.list_messages()) == ["uid-1", "uid-2"]
        fetched1 = src.fetch_message("uid-1")
        assert fetched1.labels == ("STARRED",)
        assert fetched1.rfc822_msgid == "<m1@example.com>"

        with pytest.raises(PermanentTransferError, match="not found"):
            src.fetch_message("missing-uid")

        # Delete .eml on disk to test missing file error
        (archive / "2025/1/5/uid-2.eml").unlink()
        with pytest.raises(PermanentTransferError, match="Missing .eml file"):
            src.fetch_message("uid-2")
    finally:
        src.close()

    # Test migrating an older v6 DB lacking rfc822_msgid column when opened by LocalGYBSink
    copied_sample = tmp_path / "legacy-v6"
    shutil.copytree(REPO_SAMPLES / "gyb-format", copied_sample)
    mig_sink = LocalGYBSink(copied_sample)
    mig_sink.connect()
    try:
        conn = sqlite3.connect(str(copied_sample / MSG_DB_FILENAME))
        cols = {row[1] for row in conn.execute("PRAGMA table_info(messages)").fetchall()}
        conn.close()
        assert "rfc822_msgid" in cols
    finally:
        mig_sink.close()

    # Missing DB raises ConfigurationError on source.connect()
    empty_src = LocalGYBSource(tmp_path / "nonexistent")
    with pytest.raises(ConfigurationError, match="not found"):
        empty_src.connect()
