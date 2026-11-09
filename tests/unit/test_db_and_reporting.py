"""Unit tests for SQLite JobStore and Rich/CSV/JSON reporting."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
from rich.console import Console

from ngyb.core import (
    Capability,
    ConfigurationError,
    JobState,
    PipelineRunSummary,
    StreamTelemetry,
    TransferPlan,
    TransferResult,
    TransferStatus,
)
from ngyb.db import (
    JobStore,
    default_job_db_path,
    export_job_csv,
    export_job_json,
    render_job_history,
    render_job_summary,
)


def test_job_store_lifecycle_and_reporting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NGYB_CONFIG_DIR", str(tmp_path / "cfg"))
    assert default_job_db_path() == (tmp_path / "cfg" / "jobs.db").resolve()

    store = JobStore()
    assert store.db_path == default_job_db_path()
    try:
        job = store.create_job(
            "migrate",
            "gmail://a@example.com",
            "gmail://b@example.com",
            query="is:starred",
            options={"cleanup": True},
        )
        assert store.get_job_options(job.job_id) == {"cleanup": True}
        assert store.get_job(job.job_id).state == JobState.RUNNING

        store.record_item(
            job.job_id,
            TransferResult(
                source_id="m-ok",
                status=TransferStatus.SUCCESS,
                destination_id="dst-1",
                bytes_transferred=512,
                sanitized=True,
            ),
            attempts=1,
        )
        store.record_item(
            job.job_id,
            TransferResult(
                source_id="m-fail-retry",
                status=TransferStatus.FAILED,
                error_message="429 rate limit",
                retryable=True,
            ),
            attempts=3,
        )
        store.record_item(
            job.job_id,
            TransferResult(
                source_id="m-fail-perm",
                status=TransferStatus.FAILED,
                error_message=None,
                retryable=False,
            ),
            attempts=1,
        )

        plan = TransferPlan.negotiate(Capability.STREAMING_FETCH, Capability.STREAMING_INSERT)
        summary = PipelineRunSummary(
            state=JobState.COMPLETED_WITH_ERRORS,
            plan=plan,
            total_discovered=3,
            succeeded=1,
            skipped=0,
            failed=2,
            bytes_transferred=512,
            telemetry=StreamTelemetry(
                target_streams=8,
                peak_streams=16,
                in_flight_streams=0,
                ssthresh=8,
                throttle_events=2,
                completed_operations=1,
                throughput_rps=10.5,
            ),
            avg_throughput_rps=9.25,
        )
        final_job = store.finalize_job(job.job_id, summary)
        assert final_job.state == JobState.COMPLETED_WITH_ERRORS
        assert final_job.peak_streams == 16
        assert store.failed_source_ids(job.job_id) == ["m-fail-retry", "m-fail-perm"]
        assert len(store.list_job_items(job.job_id)) == 3

        # Aborted job marking
        aborted = store.create_job("backup", "gmail://u@example.com", "local:///tmp/x")
        marked = store.mark_job_failed(aborted.job_id)
        assert marked.state == JobState.FAILED

        jobs = store.list_jobs(limit=10)
        assert len(jobs) == 2

        with pytest.raises(ConfigurationError, match="not found"):
            store.get_job("missing-id")
        with pytest.raises(ConfigurationError, match="not found"):
            store.get_job_options("missing-id")

        # Rich rendering (both explicit console and default console, with & without failures)
        buf = io.StringIO()
        con = Console(file=buf, force_terminal=False, width=120)
        all_items = store.list_job_items(job.job_id)
        render_job_summary(final_job, all_items, console=con)
        render_job_summary(aborted, (), console=con)
        render_job_history(jobs, console=con)
        text_out = buf.getvalue()
        assert job.job_id in text_out
        assert "ngyb retry" in text_out

        # Default console instantiation branch
        render_job_history([])
        render_job_summary(aborted)

        # JSON & CSV export
        json_out = tmp_path / "exports" / "report.json"
        csv_out = tmp_path / "exports" / "report.csv"
        export_job_json(final_job, all_items, json_out)
        export_job_csv(all_items, csv_out)

        parsed_json = json.loads(json_out.read_text(encoding="utf-8"))
        assert parsed_json["job"]["job_id"] == job.job_id
        assert len(parsed_json["items"]) == 3

        # Also export unfinished job (finished_at is None)
        export_job_json(aborted, (), tmp_path / "exports" / "aborted.json")

        with csv_out.open("r", encoding="utf-8") as fh:
            rows = list(csv.reader(fh))
        assert len(rows) == 4
    finally:
        store.close()
