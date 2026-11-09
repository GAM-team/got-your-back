"""Unit tests for MboxSource (including Takeout, Vault, and historic sample mboxes)."""

from __future__ import annotations

from pathlib import Path

import pytest

from gyb.core import ConfigurationError, PermanentTransferError, Source
from gyb.modules.mbox import (
    MboxSource,
    decode_rfc2047_text,
    normalize_takeout_label,
    parse_label_string,
)

REPO_SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def test_takeout_label_normalization_and_rfc2047_decoding() -> None:
    assert normalize_takeout_label("   ") == (None, False)
    assert normalize_takeout_label("^OPENED") == (None, False)
    assert normalize_takeout_label("^ARCHIVED") == (None, False)
    assert normalize_takeout_label("^DELETED") == (None, True)
    assert normalize_takeout_label("SENT MAIL") == ("SENT", False)
    assert normalize_takeout_label("RECIBIDOS") == ("INBOX", False)
    assert normalize_takeout_label("Custom/Label") == ("Custom/Label", False)

    bad_charset_hdr = "=?x-unknown-charset?B?SGVsbG8=?="
    assert decode_rfc2047_text(bad_charset_hdr) == "Hello"

    assert parse_label_string("   ") == ((), False)
    labels, deleted = parse_label_string(
        '^INBOX, "Quoted, Label", ^OPENED, ^DELETED, SENT MAIL, ^INBOX, DRAFTS'
    )
    assert labels == ("INBOX", "Quoted, Label", "SENT", "DRAFT")
    assert deleted is True


def test_real_sample_mboxes_takeout_vault_and_historic() -> None:
    takeout_src = MboxSource(REPO_SAMPLES / "google-takeout" / "takeout.mbox")
    assert isinstance(takeout_src, Source)
    assert bool(takeout_src.capabilities)
    assert takeout_src.path == (REPO_SAMPLES / "google-takeout" / "takeout.mbox").resolve()
    with takeout_src:
        ids = list(takeout_src.list_messages())
        assert len(ids) > 0
        first = takeout_src.fetch_message(ids[0])
        assert first.size_bytes > 100
        assert len(first.labels) > 0

    with MboxSource(REPO_SAMPLES / "vault-export-mbox") as vault_src:
        vault_ids = list(vault_src.list_messages())
        assert len(vault_ids) > 0
        v_msg = vault_src.fetch_message(vault_ids[0])
        assert "INBOX" in v_msg.labels
        assert "UNREAD" in v_msg.labels

    with MboxSource(REPO_SAMPLES / "historic-public-mbox") as hist_src:
        hist_ids = list(hist_src.list_messages())
        assert len(hist_ids) >= 4
        for hid in hist_ids[:4]:
            assert hist_src.fetch_message(hid).size_bytes > 0


def test_mbox_edge_cases_csv_sidecar_and_errors(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="does not exist"):
        MboxSource(tmp_path / "nope.mbox").connect()

    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    with pytest.raises(ConfigurationError, match="No .mbox or .mbx files"):
        MboxSource(empty_dir).connect()

    mbox_dir = tmp_path / "vault-sim"
    mbox_dir.mkdir()
    mbox_file = mbox_dir / "export.mbox"
    mbox_file.write_bytes(
        b"From 111.mbox@xxx Tue Apr 16 12:00:40 2019\r\n"
        b"Message-ID: <csv-1@example.com>\r\n"
        b"Date: Tue, 16 Apr 2019 12:00:40 +0000\r\n"
        b"X-Gmail-Labels: DRAFTS, STARRED\r\n"
        b"\r\n"
        b">From escaped line\r\n"
        b">>From double escaped\r\n\r\n"
        b"From plain@sender Tue Apr 16 12:05:00 2019\n"
        b"Message-ID: <msg-2@example.com>\n"
        b"\n"
        b"Body LF\n\n"
        b"From \n"
        b"Message-ID: <msg-3@example.com>\n"
        b"\n"
        b"No trailing blank line"
    )
    (mbox_dir / "labels.csv").write_text(
        'Rfc822MessageId,Labels\n<csv-1@example.com>,"^STARRED,^DELETED"\n<empty@x>,\n',
        encoding="utf-8",
    )
    (mbox_dir / "counts.csv").write_text("Account,Count\nu@example.com,2\n", encoding="utf-8")
    (mbox_dir / "extra-metadata.xml").write_text(
        "<Root><Documents>"
        "<Document><Tags><Tag TagName='Other' TagValue='x'/></Tags></Document>"
        "<Document><Tags><Tag TagName='Labels' TagValue='CustomXML'/></Tags>"
        "<Files><File><ExternalFile FileName='111.mbox'/><ExternalFile/></File></Files></Document>"
        "</Documents></Root>",
        encoding="utf-8",
    )
    (mbox_dir / "zero.mbx").write_bytes(b"")

    src = MboxSource(mbox_file)
    with pytest.raises(ConfigurationError, match="not connected"):
        list(src.list_messages())
    with pytest.raises(ConfigurationError, match="not connected"):
        src.fetch_message("x")

    with src:
        ids = list(src.list_messages())
        assert len(ids) == 3
        m1 = src.fetch_message(ids[0])
        assert b"\r\nFrom escaped line\r\n>From double escaped" in m1.raw_rfc822
        assert m1.is_draft is True
        assert m1.is_deleted is True
        assert set(m1.labels) == {"DRAFT", "CustomXML", "STARRED"}

        m2 = src.fetch_message(ids[1])
        assert m2.raw_rfc822.endswith(b"Body LF\n")

        m3 = src.fetch_message(ids[2])
        assert m3.raw_rfc822.endswith(b"No trailing blank line")

        with pytest.raises(PermanentTransferError, match="not found"):
            src.fetch_message("missing:0:99")

    with MboxSource(mbox_dir) as dir_src:
        assert len(list(dir_src.list_messages())) == 3
