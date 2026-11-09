"""Local GYB archive Sink writing YYYY/M/D/<uid>.eml files and msg-db.sqlite v6."""

from __future__ import annotations

import re
import sqlite3
import threading
from pathlib import Path
from types import TracebackType
from typing import Self

from gyb.core.capabilities import Capability
from gyb.core.exceptions import ConfigurationError
from gyb.core.models import Message, TransferResult, TransferStatus
from gyb.modules.local.schema import (
    extract_msgid_and_date,
    format_gyb_timestamp,
    open_local_gyb_db,
)

_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_uid_for_filename(uid: str) -> str:
    """Sanitize an arbitrary source ID for safe cross-platform .eml filenames."""
    cleaned = _UNSAFE_FILENAME_CHARS.sub("_", uid.strip()).strip("._")
    return cleaned or "message"


class LocalGYBSink:
    """Writes messages and metadata into a native GYB local backup directory."""

    def __init__(self, folder: Path, *, email_address: str = "local-archive") -> None:
        self._folder = folder.expanduser().resolve()
        self._email_address = email_address
        self._conn: sqlite3.Connection | None = None
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
            Capability.STREAMING_INSERT
            | Capability.MULTIPLEXED_STREAMS
            | Capability.LABEL_SUPPORT
            | Capability.SERVER_DEDUPLICATION
        )

    def connect(self) -> None:
        self._conn, _ = open_local_gyb_db(
            self._folder,
            create=True,
            email_address=self._email_address,
        )

    def _require_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise ConfigurationError("LocalGYBSink is not connected.")
        return self._conn

    def existing_uids(self) -> set[str]:
        """Return UIDs already stored in msg-db.sqlite (before or after connect)."""
        if self._conn is not None:
            with self._lock:
                rows = self._conn.execute("SELECT uid FROM uids").fetchall()
            return {str(r[0]) for r in rows}

        try:
            conn, _ = open_local_gyb_db(self._folder, create=False)
        except FileNotFoundError:
            return set()
        try:
            rows = conn.execute("SELECT uid FROM uids").fetchall()
            return {str(r[0]) for r in rows}
        finally:
            conn.close()

    def import_message(self, message: Message) -> TransferResult:
        conn = self._require_conn()
        uid = message.source_id

        with self._lock:
            existing = conn.execute(
                "SELECT message_num FROM uids WHERE uid = ?",
                (uid,),
            ).fetchone()
            if existing is not None:
                msg_num = int(existing[0])
                conn.execute("DELETE FROM labels WHERE message_num = ?", (msg_num,))
                for lbl in dict.fromkeys(message.labels):
                    conn.execute(
                        "INSERT OR IGNORE INTO labels (message_num, label) VALUES (?, ?)",
                        (msg_num, lbl),
                    )
                conn.commit()
                return TransferResult(
                    source_id=uid,
                    status=TransferStatus.SKIPPED,
                    destination_id=uid,
                )

        parsed_msgid, parsed_dt = extract_msgid_and_date(message.raw_rfc822)
        msgid = message.rfc822_msgid or parsed_msgid
        ts_str, effective_dt = format_gyb_timestamp(message.internal_date or parsed_dt)
        safe_stem = sanitize_uid_for_filename(uid)
        rel_dir = f"{effective_dt.year}/{effective_dt.month}/{effective_dt.day}"
        rel_path = f"{rel_dir}/{safe_stem}.eml"
        full_path = self._folder / rel_dir / f"{safe_stem}.eml"
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_bytes(message.raw_rfc822)

        with self._lock:
            cur = conn.execute(
                """
                INSERT INTO messages (message_filename, message_internaldate, rfc822_msgid)
                VALUES (?, ?, ?)
                """,
                (rel_path, ts_str, msgid),
            )
            msg_num = int(cur.lastrowid or 0)
            conn.execute(
                "INSERT INTO uids (message_num, uid) VALUES (?, ?)",
                (msg_num, uid),
            )
            for lbl in dict.fromkeys(message.labels):
                conn.execute(
                    "INSERT OR IGNORE INTO labels (message_num, label) VALUES (?, ?)",
                    (msg_num, lbl),
                )
            conn.commit()

        return TransferResult(
            source_id=uid,
            status=TransferStatus.SUCCESS,
            destination_id=rel_path,
            bytes_transferred=message.size_bytes,
        )

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
