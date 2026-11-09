"""Rich CLI audit reporting and CSV/JSON exporters for ngyb jobs."""

from __future__ import annotations

import csv
import json
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.table import Table

from ngyb.core.models import JobMetadata, TransferStatus
from ngyb.db.job_store import JobItemRecord


def render_job_summary(
    job: JobMetadata,
    items: Sequence[JobItemRecord] = (),
    *,
    console: Console | None = None,
) -> None:
    """Render a Rich summary table (and failed-message breakdown) for a single job."""
    out = console or Console()
    summary_table = Table(title=f"Job Summary — {job.job_id}")
    summary_table.add_column("Field", style="bold cyan")
    summary_table.add_column("Value")

    rows = [
        ("Job ID", job.job_id),
        ("Action", job.action),
        ("State", job.state.value),
        ("Source", job.source_uri),
        ("Destination", job.sink_uri),
        ("Query", job.query or "-"),
        ("Started At", job.started_at.isoformat()),
        ("Finished At", job.finished_at.isoformat() if job.finished_at else "-"),
        ("Discovered", str(job.total_discovered)),
        ("Succeeded", str(job.succeeded)),
        ("Skipped", str(job.skipped)),
        ("Failed", str(job.failed)),
        ("Bytes Transferred", f"{job.bytes_transferred:,}"),
        ("Peak HTTP/2 Streams", str(job.peak_streams)),
        ("Avg Throughput (msg/s)", f"{job.avg_throughput_rps:.2f}"),
        ("Throttle Backoffs", str(job.throttle_events)),
    ]
    for label, val in rows:
        summary_table.add_row(label, val)
    out.print(summary_table)

    failed_items = [it for it in items if it.status == TransferStatus.FAILED]
    if failed_items:
        fail_table = Table(title=f"Failed Messages ({len(failed_items)})")
        fail_table.add_column("Source ID", style="yellow")
        fail_table.add_column("Attempts", justify="right")
        fail_table.add_column("Retryable")
        fail_table.add_column("Error", style="red")
        for it in failed_items[:50]:
            fail_table.add_row(
                it.source_id,
                str(it.attempts),
                "yes" if it.retryable else "no",
                it.error_message or "-",
            )
        out.print(fail_table)
        out.print(
            f"[bold yellow]Tip:[/bold yellow] Run 'ngyb retry {job.job_id}' to retry failed items."
        )


def render_job_history(
    jobs: Sequence[JobMetadata],
    *,
    console: Console | None = None,
) -> None:
    """Render a Rich table of recent transfer jobs."""
    out = console or Console()
    table = Table(title="ngyb Job History")
    table.add_column("Job ID", style="cyan")
    table.add_column("Action")
    table.add_column("State")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("OK", justify="right", style="green")
    table.add_column("Skip", justify="right")
    table.add_column("Fail", justify="right", style="red")
    table.add_column("Peak Streams", justify="right")

    for job in jobs:
        table.add_row(
            job.job_id,
            job.action,
            job.state.value,
            job.source_uri,
            job.sink_uri,
            str(job.succeeded),
            str(job.skipped),
            str(job.failed),
            str(job.peak_streams),
        )
    out.print(table)


def export_job_json(
    job: JobMetadata,
    items: Sequence[JobItemRecord],
    output_path: Path,
) -> None:
    """Export full job metadata and per-message records as structured JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "job": {
            "job_id": job.job_id,
            "action": job.action,
            "source_uri": job.source_uri,
            "sink_uri": job.sink_uri,
            "state": job.state.value,
            "started_at": job.started_at.isoformat(),
            "finished_at": job.finished_at.isoformat() if job.finished_at else None,
            "query": job.query,
            "total_discovered": job.total_discovered,
            "succeeded": job.succeeded,
            "skipped": job.skipped,
            "failed": job.failed,
            "bytes_transferred": job.bytes_transferred,
            "peak_streams": job.peak_streams,
            "avg_throughput_rps": job.avg_throughput_rps,
            "throttle_events": job.throttle_events,
        },
        "items": [
            {
                "source_id": it.source_id,
                "status": it.status.value,
                "destination_id": it.destination_id,
                "error_message": it.error_message,
                "retryable": it.retryable,
                "attempts": it.attempts,
                "bytes_transferred": it.bytes_transferred,
                "sanitized": it.sanitized,
                "updated_at": it.updated_at.isoformat(),
            }
            for it in items
        ],
    }
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def export_job_csv(items: Sequence[JobItemRecord], output_path: Path) -> None:
    """Export per-message transfer audit rows to CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "job_id",
                "source_id",
                "status",
                "destination_id",
                "attempts",
                "retryable",
                "bytes_transferred",
                "sanitized",
                "error_message",
                "updated_at",
            ]
        )
        for it in items:
            writer.writerow(
                [
                    it.job_id,
                    it.source_id,
                    it.status.value,
                    it.destination_id or "",
                    it.attempts,
                    it.retryable,
                    it.bytes_transferred,
                    it.sanitized,
                    it.error_message or "",
                    it.updated_at.isoformat(),
                ]
            )
