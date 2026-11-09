"""Thread-safe SQLite WAL JobStore for transfer tracking and retry support."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from gyb.auth.manager import default_config_dir
from gyb.core.exceptions import ConfigurationError
from gyb.core.models import JobMetadata, JobState, TransferResult, TransferStatus
from gyb.core.pipeline import PipelineRunSummary


@dataclass(frozen=True, slots=True)
class JobItemRecord:
    """Persisted per-message audit row inside a transfer job."""

    job_id: str
    source_id: str
    status: TransferStatus
    destination_id: str | None
    error_message: str | None
    retryable: bool
    attempts: int
    bytes_transferred: int
    sanitized: bool
    updated_at: datetime


def default_job_db_path() -> Path:
    """Return default path to the SQLite job tracking database."""
    return default_config_dir() / "jobs.db"


class JobStore:
    """Persistent thread-safe SQLite store for jobs and per-message outcomes."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = (db_path or default_job_db_path()).expanduser().resolve()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._init_schema()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def db_path(self) -> Path:
        return self._db_path

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    action TEXT NOT NULL,
                    source_uri TEXT NOT NULL,
                    sink_uri TEXT NOT NULL,
                    state TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    query TEXT,
                    total_discovered INTEGER NOT NULL DEFAULT 0,
                    succeeded INTEGER NOT NULL DEFAULT 0,
                    skipped INTEGER NOT NULL DEFAULT 0,
                    failed INTEGER NOT NULL DEFAULT 0,
                    bytes_transferred INTEGER NOT NULL DEFAULT 0,
                    peak_streams INTEGER NOT NULL DEFAULT 0,
                    avg_throughput_rps REAL NOT NULL DEFAULT 0.0,
                    throttle_events INTEGER NOT NULL DEFAULT 0,
                    options_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS job_items (
                    job_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    destination_id TEXT,
                    error_message TEXT,
                    retryable INTEGER NOT NULL DEFAULT 0,
                    attempts INTEGER NOT NULL DEFAULT 1,
                    bytes_transferred INTEGER NOT NULL DEFAULT 0,
                    sanitized INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (job_id, source_id)
                );
                """
            )
            self._conn.commit()

    def create_job(
        self,
        action: str,
        source_uri: str,
        sink_uri: str,
        *,
        query: str | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> JobMetadata:
        """Create and persist a new RUNNING job record."""
        job_id = uuid.uuid4().hex[:12]
        now = datetime.now(tz=UTC)
        opts_json = json.dumps(dict(options or {}), sort_keys=True)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO jobs (
                    job_id, action, source_uri, sink_uri, state, started_at, query, options_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    action,
                    source_uri,
                    sink_uri,
                    JobState.RUNNING.value,
                    now.isoformat(),
                    query,
                    opts_json,
                ),
            )
            self._conn.commit()
        return JobMetadata(
            job_id=job_id,
            action=action,
            source_uri=source_uri,
            sink_uri=sink_uri,
            state=JobState.RUNNING,
            started_at=now,
            query=query,
        )

    def record_item(self, job_id: str, result: TransferResult, *, attempts: int = 1) -> None:
        """Upsert a per-message TransferResult in job_items."""
        now_iso = datetime.now(tz=UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO job_items (
                    job_id, source_id, status, destination_id, error_message,
                    retryable, attempts, bytes_transferred, sanitized, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    result.source_id,
                    result.status.value,
                    result.destination_id,
                    result.error_message,
                    1 if result.retryable else 0,
                    attempts,
                    result.bytes_transferred,
                    1 if result.sanitized else 0,
                    now_iso,
                ),
            )
            self._conn.commit()

    def finalize_job(self, job_id: str, summary: PipelineRunSummary) -> JobMetadata:
        """Record final job counts, state, and HTTP/2 stream telemetry."""
        finished_iso = datetime.now(tz=UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                UPDATE jobs
                SET state = ?,
                    finished_at = ?,
                    total_discovered = ?,
                    succeeded = ?,
                    skipped = ?,
                    failed = ?,
                    bytes_transferred = ?,
                    peak_streams = ?,
                    avg_throughput_rps = ?,
                    throttle_events = ?
                WHERE job_id = ?
                """,
                (
                    summary.state.value,
                    finished_iso,
                    summary.total_discovered,
                    summary.succeeded,
                    summary.skipped,
                    summary.failed,
                    summary.bytes_transferred,
                    summary.telemetry.peak_streams,
                    summary.avg_throughput_rps,
                    summary.telemetry.throttle_events,
                    job_id,
                ),
            )
            self._conn.commit()
        return self.get_job(job_id)

    def mark_job_failed(self, job_id: str) -> JobMetadata:
        """Mark an aborted job as FAILED."""
        finished_iso = datetime.now(tz=UTC).isoformat()
        with self._lock:
            self._conn.execute(
                "UPDATE jobs SET state = ?, finished_at = ? WHERE job_id = ?",
                (JobState.FAILED.value, finished_iso, job_id),
            )
            self._conn.commit()
        return self.get_job(job_id)

    @staticmethod
    def _row_to_job(row: tuple[Any, ...]) -> JobMetadata:
        return JobMetadata(
            job_id=str(row[0]),
            action=str(row[1]),
            source_uri=str(row[2]),
            sink_uri=str(row[3]),
            state=JobState(str(row[4])),
            started_at=datetime.fromisoformat(str(row[5])),
            finished_at=datetime.fromisoformat(str(row[6])) if row[6] else None,
            query=str(row[7]) if row[7] is not None else None,
            total_discovered=int(row[8]),
            succeeded=int(row[9]),
            skipped=int(row[10]),
            failed=int(row[11]),
            bytes_transferred=int(row[12]),
            peak_streams=int(row[13]),
            avg_throughput_rps=float(row[14]),
            throttle_events=int(row[15]),
        )

    def get_job(self, job_id: str) -> JobMetadata:
        """Retrieve a JobMetadata record by job_id."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT job_id, action, source_uri, sink_uri, state, started_at, finished_at,
                       query, total_discovered, succeeded, skipped, failed, bytes_transferred,
                       peak_streams, avg_throughput_rps, throttle_events
                FROM jobs
                WHERE job_id = ?
                """,
                (job_id,),
            ).fetchone()
        if row is None:
            raise ConfigurationError(f"Job {job_id!r} not found.")
        return self._row_to_job(row)

    def get_job_options(self, job_id: str) -> dict[str, Any]:
        """Retrieve stored execution options JSON for a job."""
        with self._lock:
            row = self._conn.execute(
                "SELECT options_json FROM jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        if row is None:
            raise ConfigurationError(f"Job {job_id!r} not found.")
        return dict(json.loads(str(row[0])))

    def list_jobs(self, *, limit: int = 20) -> list[JobMetadata]:
        """List recent jobs ordered newest first."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT job_id, action, source_uri, sink_uri, state, started_at, finished_at,
                       query, total_discovered, succeeded, skipped, failed, bytes_transferred,
                       peak_streams, avg_throughput_rps, throttle_events
                FROM jobs
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_job(r) for r in rows]

    def list_job_items(
        self,
        job_id: str,
        *,
        status: TransferStatus | None = None,
    ) -> list[JobItemRecord]:
        """List recorded per-message items for a job, optionally filtered by status."""
        self.get_job(job_id)
        with self._lock:
            if status is None:
                rows = self._conn.execute(
                    """
                    SELECT job_id, source_id, status, destination_id, error_message,
                           retryable, attempts, bytes_transferred, sanitized, updated_at
                    FROM job_items
                    WHERE job_id = ?
                    ORDER BY rowid ASC
                    """,
                    (job_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT job_id, source_id, status, destination_id, error_message,
                           retryable, attempts, bytes_transferred, sanitized, updated_at
                    FROM job_items
                    WHERE job_id = ? AND status = ?
                    ORDER BY rowid ASC
                    """,
                    (job_id, status.value),
                ).fetchall()
        return [
            JobItemRecord(
                job_id=str(r[0]),
                source_id=str(r[1]),
                status=TransferStatus(str(r[2])),
                destination_id=str(r[3]) if r[3] is not None else None,
                error_message=str(r[4]) if r[4] is not None else None,
                retryable=bool(r[5]),
                attempts=int(r[6]),
                bytes_transferred=int(r[7]),
                sanitized=bool(r[8]),
                updated_at=datetime.fromisoformat(str(r[9])),
            )
            for r in rows
        ]

    def failed_source_ids(self, job_id: str) -> list[str]:
        """Return all source_ids that failed in a given job."""
        return [
            item.source_id for item in self.list_job_items(job_id, status=TransferStatus.FAILED)
        ]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
