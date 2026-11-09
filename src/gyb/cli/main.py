"""Click CLI entry point for Got Your Back (gyb)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click
from rich.console import Console

from gyb import __version__
from gyb.auth import default_config_dir
from gyb.cli.auth import auth_group
from gyb.cli.options import (
    CLIContext,
    TransferOptions,
    build_tuning_from_kwargs,
    pass_ctx,
    stream_tuning_options,
)
from gyb.cli.uri import (
    EndpointSpec,
    build_sink_from_spec,
    build_source_from_spec,
    parse_endpoint,
)
from gyb.core import (
    GYBError,
    JobState,
    StreamTuningConfig,
    TransferPipeline,
    TransferResult,
)
from gyb.db import (
    export_job_csv,
    export_job_json,
    render_job_history,
    render_job_summary,
)
from gyb.modules.local import LocalGYBSink


def _execute_transfer_job(
    ctx: CLIContext,
    *,
    action: str,
    src_spec: EndpointSpec,
    dst_spec: EndpointSpec,
    tuning: StreamTuningConfig,
    options: TransferOptions,
    query: str | None = None,
    explicit_ids: list[str] | None = None,
) -> None:
    mgr = ctx.profile_manager()
    with ctx.job_store() as store:
        job = store.create_job(
            action=action,
            source_uri=src_spec.uri,
            sink_uri=dst_spec.uri,
            query=query,
            options=options.to_dict(),
        )
        try:
            source = build_source_from_spec(
                src_spec,
                profile_manager=mgr,
                options=options,
                tuning=tuning,
            )
            email_hint = src_spec.target if src_spec.scheme == "gmail" else "local-archive"
            sink = build_sink_from_spec(
                dst_spec,
                profile_manager=mgr,
                options=options,
                tuning=tuning,
                email_hint=email_hint,
            )

            skip_ids: set[str] = set()
            if isinstance(sink, LocalGYBSink) and not options.no_resume and explicit_ids is None:
                skip_ids = sink.existing_uids()

            def _on_result(res: TransferResult, attempts: int) -> None:
                store.record_item(job.job_id, res, attempts=attempts)

            pipeline = TransferPipeline(
                source,
                sink,
                tuning=tuning,
                on_result=_on_result,
                skip_source_ids=skip_ids,
            )
            summary = pipeline.run(query=query, explicit_ids=explicit_ids)
            final_job = store.finalize_job(job.job_id, summary)
            items = store.list_job_items(job.job_id)
            render_job_summary(final_job, items, console=ctx.console)
            if final_job.state != JobState.COMPLETED:
                raise click.ClickException(
                    f"Job {final_job.job_id} completed with {final_job.failed} failed message(s)."
                )
        except click.ClickException:
            raise
        except GYBError as exc:
            store.mark_job_failed(job.job_id)
            raise click.ClickException(str(exc)) from exc


@click.group()
@click.version_option(__version__, prog_name="gyb")
@click.option(
    "--config-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=None,
    help="Override GYB configuration and job database directory.",
)
@click.pass_context
def cli(click_ctx: click.Context, config_dir: Path | None) -> None:
    """Got Your Back (gyb) — HTTP/2-multiplexed, DPoP-bound email backup & migration."""
    resolved_dir = (config_dir or default_config_dir()).expanduser().resolve()
    click_ctx.obj = CLIContext(config_dir=resolved_dir, console=Console())


cli.add_command(auth_group)


@cli.command("backup")
@click.argument("email")
@click.argument("dest_folder", required=False, default=None)
@click.option("--profile", default=None, help="Authentication profile name.")
@click.option("--subject", default=None, help="ADC Domain-Wide Delegation subject override.")
@click.option("--search", "query", default=None, help="Gmail search query filter.")
@click.option("--spam-trash", is_flag=True, default=False, help="Include SPAM and TRASH messages.")
@click.option(
    "--no-resume", is_flag=True, default=False, help="Re-transfer already backed up UIDs."
)
@stream_tuning_options
@pass_ctx
def backup_cmd(
    ctx: CLIContext,
    /,
    email: str,
    dest_folder: str | None,
    profile: str | None,
    subject: str | None,
    query: str | None,
    spam_trash: bool,
    no_resume: bool,
    **tuning_kwargs: Any,
) -> None:
    """Back up a Gmail mailbox to a local GYB archive directory."""
    try:
        tuning = build_tuning_from_kwargs(tuning_kwargs)
        src_spec = parse_endpoint(email, for_source=True, default_email_scheme="gmail")
        folder_str = dest_folder or f"GYB-GMail-Backup-{src_spec.target}"
        dst_spec = parse_endpoint(folder_str, for_source=False)
    except GYBError as exc:
        raise click.ClickException(str(exc)) from exc

    _execute_transfer_job(
        ctx,
        action="backup",
        src_spec=src_spec,
        dst_spec=dst_spec,
        tuning=tuning,
        options=TransferOptions(
            source_profile=profile,
            source_subject=subject,
            include_spam_trash=spam_trash,
            no_resume=no_resume,
        ),
        query=query,
    )


@cli.command("restore")
@click.argument("source_path")
@click.argument("destination")
@click.option("--profile", default=None, help="Authentication profile name.")
@click.option("--subject", default=None, help="ADC Domain-Wide Delegation admin/user subject.")
@click.option("--strip-labels", is_flag=True, default=False, help="Do not restore source labels.")
@click.option("--label-prefix", default=None, help="Nest restored user labels under this prefix.")
@click.option("--label-restored", default=None, help="Apply an extra Gmail label to restored mail.")
@click.option(
    "--cleanup", is_flag=True, default=False, help="Proactively sanitize RFC 822 headers."
)
@click.option("--cleanup-from", default=None, help="Fallback From address when sanitizing headers.")
@click.option(
    "--use-insert", is_flag=True, default=False, help="Use Gmail messages.insert endpoint."
)
@stream_tuning_options
@pass_ctx
def restore_cmd(
    ctx: CLIContext,
    /,
    source_path: str,
    destination: str,
    profile: str | None,
    subject: str | None,
    strip_labels: bool,
    label_prefix: str | None,
    label_restored: str | None,
    cleanup: bool,
    cleanup_from: str | None,
    use_insert: bool,
    **tuning_kwargs: Any,
) -> None:
    """Restore a local GYB archive or mbox export into Gmail or Google Groups."""
    try:
        tuning = build_tuning_from_kwargs(tuning_kwargs)
        src_spec = parse_endpoint(source_path, for_source=True)
        dst_spec = parse_endpoint(destination, for_source=False, default_email_scheme="gmail")
    except GYBError as exc:
        raise click.ClickException(str(exc)) from exc

    _execute_transfer_job(
        ctx,
        action="restore",
        src_spec=src_spec,
        dst_spec=dst_spec,
        tuning=tuning,
        options=TransferOptions(
            dest_profile=profile,
            dest_subject=subject,
            strip_labels=strip_labels,
            label_prefix=label_prefix,
            label_restored=label_restored,
            cleanup=cleanup,
            cleanup_from=cleanup_from,
            use_insert=use_insert,
        ),
    )


@cli.command("migrate")
@click.argument("source_uri")
@click.argument("dest_uri")
@click.option("--source-profile", default=None, help="Auth profile for the Source.")
@click.option("--dest-profile", default=None, help="Auth profile for the Destination.")
@click.option("--source-subject", default=None, help="ADC subject override for Source.")
@click.option("--dest-subject", default=None, help="ADC subject override for Destination.")
@click.option("--search", "query", default=None, help="Source search query filter.")
@click.option("--spam-trash", is_flag=True, default=False, help="Include SPAM/TRASH from Source.")
@click.option("--strip-labels", is_flag=True, default=False, help="Strip labels on Destination.")
@click.option("--label-prefix", default=None, help="Prefix labels on Destination.")
@click.option("--label-restored", default=None, help="Tag imported messages with this label.")
@click.option(
    "--cleanup", is_flag=True, default=False, help="Proactively sanitize RFC 822 headers."
)
@click.option("--cleanup-from", default=None, help="Fallback From address when sanitizing.")
@click.option(
    "--preserve-threads", is_flag=True, default=False, help="Preserve threadId when valid."
)
@stream_tuning_options
@pass_ctx
def migrate_cmd(
    ctx: CLIContext,
    /,
    source_uri: str,
    dest_uri: str,
    source_profile: str | None,
    dest_profile: str | None,
    source_subject: str | None,
    dest_subject: str | None,
    query: str | None,
    spam_trash: bool,
    strip_labels: bool,
    label_prefix: str | None,
    label_restored: str | None,
    cleanup: bool,
    cleanup_from: str | None,
    preserve_threads: bool,
    **tuning_kwargs: Any,
) -> None:
    """Stream messages directly from any Source URI to any Destination URI."""
    try:
        tuning = build_tuning_from_kwargs(tuning_kwargs)
        src_spec = parse_endpoint(source_uri, for_source=True, default_email_scheme="gmail")
        dst_spec = parse_endpoint(dest_uri, for_source=False, default_email_scheme="gmail")
    except GYBError as exc:
        raise click.ClickException(str(exc)) from exc

    _execute_transfer_job(
        ctx,
        action="migrate",
        src_spec=src_spec,
        dst_spec=dst_spec,
        tuning=tuning,
        options=TransferOptions(
            source_profile=source_profile,
            dest_profile=dest_profile,
            source_subject=source_subject,
            dest_subject=dest_subject,
            include_spam_trash=spam_trash,
            strip_labels=strip_labels,
            label_prefix=label_prefix,
            label_restored=label_restored,
            cleanup=cleanup,
            cleanup_from=cleanup_from,
            preserve_threads=preserve_threads,
        ),
        query=query,
    )


@cli.command("retry")
@click.argument("job_id")
@stream_tuning_options
@pass_ctx
def retry_cmd(ctx: CLIContext, /, job_id: str, **tuning_kwargs: Any) -> None:
    """Retry only the failed messages from a previous job ID."""
    try:
        tuning = build_tuning_from_kwargs(tuning_kwargs)
        with ctx.job_store() as store:
            orig_job = store.get_job(job_id)
            opts = TransferOptions.from_dict(store.get_job_options(job_id))
            failed_ids = store.failed_source_ids(job_id)
        src_spec = parse_endpoint(orig_job.source_uri, for_source=True)
        dst_spec = parse_endpoint(orig_job.sink_uri, for_source=False)
    except GYBError as exc:
        raise click.ClickException(str(exc)) from exc

    if not failed_ids:
        ctx.console.print(f"[green]Job {job_id} has no failed items to retry.[/green]")
        return

    _execute_transfer_job(
        ctx,
        action="retry",
        src_spec=src_spec,
        dst_spec=dst_spec,
        tuning=tuning,
        options=opts,
        explicit_ids=failed_ids,
    )


@cli.command("report")
@click.argument("job_id", required=False, default=None)
@click.option("--limit", type=int, default=20, show_default=True, help="Max jobs in history table.")
@click.option(
    "--export-json",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Export job details and items to a JSON file.",
)
@click.option(
    "--export-csv",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Export per-message audit records to a CSV file.",
)
@pass_ctx
def report_cmd(
    ctx: CLIContext,
    job_id: str | None,
    limit: int,
    export_json: Path | None,
    export_csv: Path | None,
) -> None:
    """View Rich job history or inspect/export a specific job's audit log."""
    try:
        with ctx.job_store() as store:
            if job_id is None:
                jobs = store.list_jobs(limit=limit)
                render_job_history(jobs, console=ctx.console)
                return

            job = store.get_job(job_id)
            items = store.list_job_items(job_id)
            render_job_summary(job, items, console=ctx.console)
            if export_json is not None:
                export_job_json(job, items, export_json)
                ctx.console.print(f"Exported JSON report to {export_json}")
            if export_csv is not None:
                export_job_csv(items, export_csv)
                ctx.console.print(f"Exported CSV report to {export_csv}")
    except GYBError as exc:
        raise click.ClickException(str(exc)) from exc
