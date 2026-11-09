"""Local GYB archive Source reading msg-db.sqlite and YYYY/M/D/<uid>.eml files."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import Self

from gyb.core.capabilities import Capability
from gyb.core.exceptions import ConfigurationError, PermanentTransferError
from gyb.core.models import Message
from gyb.modules.local.schema import (
    extract_msgid_and_date,
    open_local_gyb_db,
    parse_gyb_timestamp,
)


class LocalGYBSource:
    """Reads messages and labels from a native GYB local backup directory."""

    def __init__(self, folder: Path) -> None:
        self._folder = folder.expanduser().resolve()
        self._conn: sqlite3.Connection | None = None
        self._has_msgid_col = False
        self._lock = threading.Lock()

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def folder(self) -> Path:
        return self._folder

    @property
    def capabilities(self) -> Capability:
        return (
            Capability.STREAMING_FETCH | Capability.MULTIPLEXED_STREAMS | Capability.LABEL_SUPPORT
        )

    def connect(self) -> None:
        try:
            self._conn, self._has_msgid_col = open_local_gyb_db(self._folder, create=False)
        except FileNotFoundError as exc:
            raise ConfigurationError(str(exc)) from exc

    def _require_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise ConfigurationError("LocalGYBSource is not connected.")
        return self._conn

    def list_messages(self, query: str | None = None) -> Iterator[str]:
        _ = query
        conn = self._require_conn()
        with self._lock:
            rows = conn.execute(
                """
                SELECT COALESCE(u.uid, CAST(m.message_num AS TEXT))
                FROM messages m
                LEFT JOIN uids u ON u.message_num = m.message_num
                ORDER BY m.message_num ASC
                """
            ).fetchall()
        for (uid,) in rows:
            yield str(uid)

    def fetch_message(self, source_id: str) -> Message:
        conn = self._require_conn()
        sql = (
            """
            SELECT m.message_num, m.message_filename, m.message_internaldate, m.rfc822_msgid
            FROM messages m
            LEFT JOIN uids u ON u.message_num = m.message_num
            WHERE u.uid = ? OR (u.uid IS NULL AND CAST(m.message_num AS TEXT) = ?)
            """
            if self._has_msgid_col
            else """
            SELECT m.message_num, m.message_filename, m.message_internaldate, NULL
            FROM messages m
            LEFT JOIN uids u ON u.message_num = m.message_num
            WHERE u.uid = ? OR (u.uid IS NULL AND CAST(m.message_num AS TEXT) = ?)
            """
        )
        with self._lock:
            row = conn.execute(sql, (source_id, source_id)).fetchone()
            if row is None:
                raise PermanentTransferError(f"UID {source_id!r} not found in {self._folder}")
            msg_num, rel_filename, raw_internaldate, db_msgid = row
            label_rows = conn.execute(
                "SELECT label FROM labels WHERE message_num = ? ORDER BY rowid ASC",
                (msg_num,),
            ).fetchall()

        eml_path = self._folder / Path(str(rel_filename))
        if not eml_path.is_file():
            raise PermanentTransferError(f"Missing .eml file for {source_id!r}: {eml_path}")
        raw_bytes = eml_path.read_bytes()

        labels = tuple(str(lbl) for (lbl,) in label_rows)
        parsed_msgid, parsed_dt = extract_msgid_and_date(raw_bytes)
        internal_dt = parse_gyb_timestamp(raw_internaldate) or parsed_dt
        msgid = str(db_msgid) if db_msgid else parsed_msgid
        is_draft = any(lbl.upper() == "DRAFT" for lbl in labels)

        return Message(
            source_id=source_id,
            raw_rfc822=raw_bytes,
            rfc822_msgid=msgid,
            internal_date=internal_dt,
            labels=labels,
            is_draft=is_draft,
        )

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
