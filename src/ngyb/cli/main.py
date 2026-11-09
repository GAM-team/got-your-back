"""Click CLI entry point for Got Your Back (ngyb)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.table import Table

from ngyb import __version__
from ngyb.auth import (
    OAuthProfile,
    ProfileManager,
    SignerConfig,
    SignerType,
    available_signer_types,
    default_config_dir,
)
from ngyb.cli.options import build_tuning_from_kwargs, stream_tuning_options
from ngyb.cli.uri import (
    EndpointSpec,
    build_sink_from_spec,
    build_source_from_spec,
    parse_endpoint,
)
from ngyb.core import (
    JobState,
    NGYBError,
    StreamTuningConfig,
    TransferPipeline,
    TransferResult,
)
from ngyb.db import (
    JobStore,
    export_job_csv,
    export_job_json,
    render_job_history,
    render_job_summary,
)
from ngyb.modules.local import LocalGYBSink


@dataclass(slots=True)
class CLIContext:
    """Shared CLI runtime configuration."""

    config_dir: Path
    console: Console

    def profile_manager(self) -> ProfileManager:
        return ProfileManager(self.config_dir)

    def job_store(self) -> JobStore:
        return JobStore(self.config_dir / "jobs.db")


pass_ctx = click.make_pass_decorator(CLIContext)


def _execute_transfer_job(
    ctx: CLIContext,
    *,
    action: str,
    src_spec: EndpointSpec,
    dst_spec: EndpointSpec,
    tuning: StreamTuningConfig,
    source_profile: str | None = None,
    dest_profile: str | None = None,
    source_subject: str | None = None,
    dest_subject: str | None = None,
    query: str | None = None,
    include_spam_trash: bool = False,
    strip_labels: bool = False,
    label_prefix: str | None = None,
    label_restored: str | None = None,
    cleanup: bool = False,
    cleanup_from: str | None = None,
    use_insert: bool = False,
    preserve_threads: bool = False,
    no_resume: bool = False,
    explicit_ids: list[str] | None = None,
) -> None:
    mgr = ctx.profile_manager()
    store = ctx.job_store()
    options_dict: dict[str, Any] = {
        "source_profile": source_profile,
        "dest_profile": dest_profile,
        "source_subject": source_subject,
        "dest_subject": dest_subject,
        "include_spam_trash": include_spam_trash,
        "strip_labels": strip_labels,
        "label_prefix": label_prefix,
        "label_restored": label_restored,
        "cleanup": cleanup,
        "cleanup_from": cleanup_from,
        "use_insert": use_insert,
        "preserve_threads": preserve_threads,
    }
    job = store.create_job(
        action=action,
        source_uri=src_spec.uri,
        sink_uri=dst_spec.uri,
        query=query,
        options=options_dict,
    )
    try:
        source = build_source_from_spec(
            src_spec,
            profile_manager=mgr,
            profile_name=source_profile,
            subject=source_subject,
            tuning=tuning,
            include_spam_trash=include_spam_trash,
        )
        email_hint = src_spec.target if src_spec.scheme == "gmail" else "local-archive"
        sink = build_sink_from_spec(
            dst_spec,
            profile_manager=mgr,
            profile_name=dest_profile,
            subject=dest_subject,
            tuning=tuning,
            email_hint=email_hint,
            strip_labels=strip_labels,
            label_prefix=label_prefix,
            label_restored=label_restored,
            cleanup=cleanup,
            cleanup_from=cleanup_from,
            use_insert=use_insert,
            preserve_threads=preserve_threads,
        )

        skip_ids: set[str] = set()
        if isinstance(sink, LocalGYBSink) and not no_resume and explicit_ids is None:
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
    except NGYBError as exc:
        store.mark_job_failed(job.job_id)
        raise click.ClickException(str(exc)) from exc
    finally:
        store.close()


@click.group()
@click.version_option(__version__, prog_name="ngyb")
@click.option(
    "--config-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=None,
    help="Override ngyb configuration and job database directory.",
)
@click.pass_context
def cli(click_ctx: click.Context, config_dir: Path | None) -> None:
    """Got Your Back (ngyb) — HTTP/2-multiplexed, DPoP-bound email backup & migration."""
    resolved_dir = (config_dir or default_config_dir()).expanduser().resolve()
    click_ctx.obj = CLIContext(config_dir=resolved_dir, console=Console())


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
    except NGYBError as exc:
        raise click.ClickException(str(exc)) from exc

    _execute_transfer_job(
        ctx,
        action="backup",
        src_spec=src_spec,
        dst_spec=dst_spec,
        tuning=tuning,
        source_profile=profile,
        source_subject=subject,
        query=query,
        include_spam_trash=spam_trash,
        no_resume=no_resume,
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
    except NGYBError as exc:
        raise click.ClickException(str(exc)) from exc

    _execute_transfer_job(
        ctx,
        action="restore",
        src_spec=src_spec,
        dst_spec=dst_spec,
        tuning=tuning,
        dest_profile=profile,
        dest_subject=subject,
        strip_labels=strip_labels,
        label_prefix=label_prefix,
        label_restored=label_restored,
        cleanup=cleanup,
        cleanup_from=cleanup_from,
        use_insert=use_insert,
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
    except NGYBError as exc:
        raise click.ClickException(str(exc)) from exc

    _execute_transfer_job(
        ctx,
        action="migrate",
        src_spec=src_spec,
        dst_spec=dst_spec,
        tuning=tuning,
        source_profile=source_profile,
        dest_profile=dest_profile,
        source_subject=source_subject,
        dest_subject=dest_subject,
        query=query,
        include_spam_trash=spam_trash,
        strip_labels=strip_labels,
        label_prefix=label_prefix,
        label_restored=label_restored,
        cleanup=cleanup,
        cleanup_from=cleanup_from,
        preserve_threads=preserve_threads,
    )


@cli.command("retry")
@click.argument("job_id")
@stream_tuning_options
@pass_ctx
def retry_cmd(ctx: CLIContext, job_id: str, **tuning_kwargs: Any) -> None:
    """Retry only the failed messages from a previous job ID."""
    store = ctx.job_store()
    try:
        tuning = build_tuning_from_kwargs(tuning_kwargs)
        orig_job = store.get_job(job_id)
        opts = store.get_job_options(job_id)
        failed_ids = store.failed_source_ids(job_id)
        src_spec = parse_endpoint(orig_job.source_uri, for_source=True)
        dst_spec = parse_endpoint(orig_job.sink_uri, for_source=False)
    except NGYBError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        store.close()

    if not failed_ids:
        ctx.console.print(f"[green]Job {job_id} has no failed items to retry.[/green]")
        return

    _execute_transfer_job(
        ctx,
        action="retry",
        src_spec=src_spec,
        dst_spec=dst_spec,
        tuning=tuning,
        source_profile=opts.get("source_profile"),
        dest_profile=opts.get("dest_profile"),
        source_subject=opts.get("source_subject"),
        dest_subject=opts.get("dest_subject"),
        include_spam_trash=bool(opts.get("include_spam_trash", False)),
        strip_labels=bool(opts.get("strip_labels", False)),
        label_prefix=opts.get("label_prefix"),
        label_restored=opts.get("label_restored"),
        cleanup=bool(opts.get("cleanup", False)),
        cleanup_from=opts.get("cleanup_from"),
        use_insert=bool(opts.get("use_insert", False)),
        preserve_threads=bool(opts.get("preserve_threads", False)),
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
    store = ctx.job_store()
    try:
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
    except NGYBError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        store.close()


@cli.group("auth")
def auth_group() -> None:
    """Manage mandatory DPoP OAuth 2.0 and ADC authentication profiles."""


@auth_group.command("signers")
@pass_ctx
def auth_signers_cmd(ctx: CLIContext) -> None:
    """List DPoP signer backends supported on the current operating system."""
    table = Table(title="Available DPoP Signers on This Platform")
    table.add_column("Signer", style="cyan")
    for st in available_signer_types():
        table.add_row(st.value)
    ctx.console.print(table)


@auth_group.command("setup-oauth")
@click.argument("name")
@click.option(
    "--client-secrets",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Path to Google OAuth client_secrets.json.",
)
@click.option(
    "--signer",
    "signer_name",
    default=SignerType.SOFTWARE.value,
    show_default=True,
    help="DPoP signer backend (see 'ngyb auth signers').",
)
@click.option("--email", default=None, help="Optional Google account login hint.")
@click.option("--se-label", default=None, help="macOS Secure Enclave key label.")
@click.option("--cert-subject", default=None, help="Windows CNG certificate subject.")
@click.option("--cert-thumbprint", default=None, help="Windows CNG certificate thumbprint.")
@click.option("--tpm-handle", type=int, default=None, help="Linux TPM 2.0 persistent handle.")
@click.option("--ecp-config", default=None, help="Google ECP JSON configuration path.")
@click.option("--piv-slot", default=None, help="YubiKey PIV slot (default 9c).")
@click.option("--yubikey-serial", type=int, default=None, help="YubiKey serial number.")
@click.option("--yubikey-pin", default=None, help="YubiKey PIV PIN.")
@click.option(
    "--no-browser", is_flag=True, default=False, help="Do not launch browser automatically."
)
@pass_ctx
def auth_setup_oauth_cmd(
    ctx: CLIContext,
    name: str,
    client_secrets: Path,
    signer_name: str,
    email: str | None,
    se_label: str | None,
    cert_subject: str | None,
    cert_thumbprint: str | None,
    tpm_handle: int | None,
    ecp_config: str | None,
    piv_slot: str | None,
    yubikey_serial: int | None,
    yubikey_pin: str | None,
    no_browser: bool,
) -> None:
    """Authorize a DPoP-bound end-user OAuth 2.0 profile."""
    try:
        signer_type = SignerType(signer_name)
    except ValueError as exc:
        valid = ", ".join(s.value for s in available_signer_types())
        raise click.ClickException(
            f"Unknown signer {signer_name!r}; supported on this OS: {valid}"
        ) from exc

    cfg = SignerConfig(
        signer_type=signer_type,
        key_id=name,
        label=se_label,
        subject=cert_subject,
        cert_thumbprint=cert_thumbprint,
        tpm_handle=tpm_handle,
        ecp_config_path=ecp_config,
        piv_slot=piv_slot,
        yubikey_serial=yubikey_serial,
    )
    try:
        prof = ctx.profile_manager().setup_oauth_profile(
            name,
            client_secrets,
            signer_config=cfg,
            email=email,
            open_browser=not no_browser,
            yubikey_pin=yubikey_pin,
        )
    except NGYBError as exc:
        raise click.ClickException(str(exc)) from exc

    ctx.console.print(
        f"[green]Saved DPoP OAuth profile {prof.name!r} "
        f"(signer={prof.signer.signer_type.value}, jkt={prof.signer.dpop_thumbprint}).[/green]"
    )


@auth_group.command("setup-adc")
@click.argument("name")
@click.option("--subject", default=None, help="Domain-Wide Delegation subject email.")
@click.option(
    "--signer",
    "signer_name",
    default=None,
    help="Optional DPoP signer if ADC resolves to end-user credentials.",
)
@pass_ctx
def auth_setup_adc_cmd(
    ctx: CLIContext,
    name: str,
    subject: str | None,
    signer_name: str | None,
) -> None:
    """Create an Application Default Credentials profile (SA, DwD, GCE, WIF)."""
    signer_cfg: SignerConfig | None = None
    if signer_name is not None:
        try:
            signer_cfg = SignerConfig(signer_type=SignerType(signer_name), key_id=name)
        except ValueError as exc:
            raise click.ClickException(f"Unknown signer {signer_name!r}.") from exc

    try:
        prof = ctx.profile_manager().setup_adc_profile(
            name,
            subject=subject,
            signer_config=signer_cfg,
        )
    except NGYBError as exc:
        raise click.ClickException(str(exc)) from exc

    ctx.console.print(
        f"[green]Saved ADC profile {prof.name!r} (subject={prof.subject or 'none'}).[/green]"
    )


@auth_group.command("list")
@pass_ctx
def auth_list_cmd(ctx: CLIContext) -> None:
    """List saved authentication profiles."""
    profiles = ctx.profile_manager().list_profiles()
    table = Table(title="Configured Authentication Profiles")
    table.add_column("Name", style="cyan")
    table.add_column("Kind")
    table.add_column("Identity / Subject")
    table.add_column("DPoP Signer")
    table.add_column("DPoP Thumbprint (jkt)")
    for prof in profiles:
        if isinstance(prof, OAuthProfile):
            table.add_row(
                prof.name,
                prof.kind.value,
                prof.email or "-",
                prof.signer.signer_type.value,
                prof.signer.dpop_thumbprint or "-",
            )
        else:
            table.add_row(
                prof.name,
                prof.kind.value,
                prof.subject or "(ADC default)",
                prof.signer.signer_type.value if prof.signer else "-",
                prof.signer.dpop_thumbprint if prof.signer and prof.signer.dpop_thumbprint else "-",
            )
    ctx.console.print(table)


@auth_group.command("info")
@click.argument("name")
@pass_ctx
def auth_info_cmd(ctx: CLIContext, name: str) -> None:
    """Show detailed metadata for an authentication profile."""
    try:
        prof = ctx.profile_manager().get_profile(name)
    except NGYBError as exc:
        raise click.ClickException(str(exc)) from exc

    table = Table(title=f"Profile — {prof.name}")
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    table.add_row("Kind", prof.kind.value)
    table.add_row("Scopes", ", ".join(prof.scopes))
    if isinstance(prof, OAuthProfile):
        table.add_row("Email", prof.email or "-")
        table.add_row("DPoP Signer", prof.signer.signer_type.value)
        table.add_row("DPoP Thumbprint", prof.signer.dpop_thumbprint or "-")
    else:
        table.add_row("Subject", prof.subject or "-")
        table.add_row("DPoP Signer", prof.signer.signer_type.value if prof.signer else "-")
    ctx.console.print(table)


@auth_group.command("delete")
@click.argument("name")
@pass_ctx
def auth_delete_cmd(ctx: CLIContext, name: str) -> None:
    """Delete a saved authentication profile."""
    try:
        ctx.profile_manager().delete_profile(name)
    except NGYBError as exc:
        raise click.ClickException(str(exc)) from exc
    ctx.console.print(f"[yellow]Deleted profile {name!r}.[/yellow]")
