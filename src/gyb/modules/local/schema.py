"""SQLite msg-db.sqlite v6 schema and helpers for native GYB local archives."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from email import policy
from email.parser import BytesHeaderParser
from email.utils import parsedate_to_datetime
from pathlib import Path

MSG_DB_FILENAME = "msg-db.sqlite"
GYB_DB_VERSION = "6"
MIN_SAFE_EPOCH_SECONDS = 86400


def extract_msgid_and_date(raw_rfc822: bytes) -> tuple[str | None, datetime | None]:
    """Extract Message-ID and parsed Date header from raw RFC 822 bytes."""
    headers = BytesHeaderParser(policy=policy.compat32).parsebytes(raw_rfc822)
    raw_msgid = headers.get("Message-ID")
    msgid = raw_msgid.strip() if raw_msgid else None

    parsed_dt: datetime | None = None
    raw_date = headers.get("Date")
    if raw_date:
        try:
            dt = parsedate_to_datetime(raw_date)
            parsed_dt = dt.astimezone(UTC) if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
        except (TypeError, ValueError, IndexError):
            parsed_dt = None
    return msgid, parsed_dt


def parse_gyb_timestamp(value: str | None) -> datetime | None:
    """Parse legacy GYB SQLite message_internaldate strings (with optional fractional secs)."""
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt.astimezone(UTC) if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def format_gyb_timestamp(dt: datetime | None) -> tuple[str, datetime]:
    """Clamp and format an internal date for SQLite and YYYY/M/D directory layout."""
    effective = (
        dt.astimezone(UTC)
        if dt is not None and dt.tzinfo is not None
        else (dt.replace(tzinfo=UTC) if dt is not None else datetime.now(tz=UTC))
    )
    if effective.timestamp() < MIN_SAFE_EPOCH_SECONDS:
        effective = datetime.fromtimestamp(MIN_SAFE_EPOCH_SECONDS, tz=UTC)
    return effective.strftime("%Y-%m-%d %H:%M:%S"), effective


def open_local_gyb_db(
    folder: Path,
    *,
    create: bool,
    email_address: str = "local-archive",
) -> tuple[sqlite3.Connection, bool]:
    """Open (and optionally initialize/migrate) a GYB v6 msg-db.sqlite database.

    Returns ``(connection, has_rfc822_msgid_column)``.
    """
    db_path = folder / MSG_DB_FILENAME
    if not create and not db_path.is_file():
        raise FileNotFoundError(f"GYB SQLite database not found: {db_path}")

    folder.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.execute("PRAGMA synchronous = NORMAL")

    if create:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS messages (
                message_num INTEGER PRIMARY KEY,
                message_filename TEXT,
                message_internaldate TIMESTAMP,
                rfc822_msgid TEXT
            );
            CREATE TABLE IF NOT EXISTS labels (
                message_num INTEGER,
                label TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS labelidx ON labels (message_num, label);
            CREATE TABLE IF NOT EXISTS uids (
                message_num INTEGER,
                uid TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS settings (
                name TEXT PRIMARY KEY,
                value TEXT
            );
            """
        )
        cols = {row[1] for row in conn.execute("PRAGMA table_info(messages)").fetchall()}
        if "rfc822_msgid" not in cols:
            conn.execute("ALTER TABLE messages ADD COLUMN rfc822_msgid TEXT")
            cols.add("rfc822_msgid")
        conn.execute(
            "INSERT OR IGNORE INTO settings (name, value) VALUES ('email_address', ?)",
            (email_address,),
        )
        conn.execute(
            "INSERT OR REPLACE INTO settings (name, value) VALUES ('db_version', ?)",
            (GYB_DB_VERSION,),
        )
        conn.commit()
        return conn, True

    cols = {row[1] for row in conn.execute("PRAGMA table_info(messages)").fetchall()}
    return conn, ("rfc822_msgid" in cols)
