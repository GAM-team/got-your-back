"""Unit tests for LocalGYBSource and LocalGYBSink (including real samples/gyb-format)."""

from __future__ import annotations

import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gyb.core import (
    ConfigurationError,
    Message,
    PermanentTransferError,
    Sink,
    Source,
    TransferStatus,
)
from gyb.modules.local import (
    MSG_DB_FILENAME,
    LocalGYBSink,
    LocalGYBSource,
    sanitize_uid_for_filename,
)
from gyb.modules.local.schema import format_gyb_timestamp, parse_gyb_timestamp

REPO_SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def test_real_gyb_format_sample_archive() -> None:
    sample_dir = REPO_SAMPLES / "gyb-format"
    src = LocalGYBSource(sample_dir)
    assert isinstance(src, Source)
    assert bool(src.capabilities)
    assert src.folder == sample_dir.resolve()
    with src:
        uids = list(src.list_messages())
        assert len(uids) == 11
        assert "16a281f4eb2462ec" in uids
        msg = src.fetch_message("16a281f4eb2462ec")
        assert msg.size_bytes > 1000
        assert "top/nested" in msg.labels
        assert "INBOX" in msg.labels
        assert msg.internal_date is not None

        baddate_uid = uids[-1]
        bad_msg = src.fetch_message(baddate_uid)
        assert bad_msg.internal_date is not None
    src.close()


def test_local_sink_and_source_round_trip_and_schema_migration(tmp_path: Path) -> None:
    assert sanitize_uid_for_filename("  ../weird:id/1  ") == "weird_id_1"
    assert sanitize_uid_for_filename("...") == "message"
    assert parse_gyb_timestamp(None) is None
    assert parse_gyb_timestamp("   ") is None
    assert parse_gyb_timestamp("not-a-timestamp") is None
    assert parse_gyb_timestamp("2024-05-01T12:00:00+02:00") is not None

    ts_str, clamped = format_gyb_timestamp(datetime(1970, 1, 1, 0, 0, 1))
    assert ts_str.startswith("1970-01-02")
    assert clamped.tzinfo == UTC
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

    with sink:
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

        r1_dup = sink.import_message(m1.with_updates(labels=("STARRED",)))
        assert r1_dup.status == TransferStatus.SKIPPED

        m2 = Message(
            source_id="uid-2",
            raw_rfc822=b"Date: totally-invalid-date\r\nSubject: test\r\n\r\nBody",
            internal_date=datetime(2025, 1, 5, 8, 30, 0, tzinfo=UTC),
        )
        assert sink.import_message(m2).status == TransferStatus.SUCCESS
    sink.close()

    assert sink.existing_uids() == {"uid-1", "uid-2"}

    src = LocalGYBSource(archive)
    with pytest.raises(ConfigurationError, match="not connected"):
        list(src.list_messages())
    with pytest.raises(ConfigurationError, match="not connected"):
        src.fetch_message("uid-1")

    with src:
        assert list(src.list_messages()) == ["uid-1", "uid-2"]
        fetched1 = src.fetch_message("uid-1")
        assert fetched1.labels == ("STARRED",)
        assert fetched1.rfc822_msgid == "<m1@example.com>"

        with pytest.raises(PermanentTransferError, match="not found"):
            src.fetch_message("missing-uid")

        (archive / "2025/1/5/uid-2.eml").unlink()
        with pytest.raises(PermanentTransferError, match="Missing .eml file"):
            src.fetch_message("uid-2")

    copied_sample = tmp_path / "legacy-v6"
    shutil.copytree(REPO_SAMPLES / "gyb-format", copied_sample)
    with LocalGYBSink(copied_sample):
        conn = sqlite3.connect(str(copied_sample / MSG_DB_FILENAME))
        cols = {row[1] for row in conn.execute("PRAGMA table_info(messages)").fetchall()}
        conn.close()
        assert "rfc822_msgid" in cols

    empty_src = LocalGYBSource(tmp_path / "nonexistent")
    with pytest.raises(ConfigurationError, match="not found"):
        empty_src.connect()
