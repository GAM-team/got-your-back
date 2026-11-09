"""Authentication profile subcommands ('gyb auth ...') for DPoP OAuth and ADC."""

from __future__ import annotations

from pathlib import Path

import click
from rich.table import Table

from gyb.auth import (
    OAuthProfile,
    SignerConfig,
    SignerType,
    available_signer_types,
)
from gyb.cli.options import CLIContext, pass_ctx
from gyb.core.exceptions import GYBError


@click.group("auth")
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
    help="DPoP signer backend (see 'gyb auth signers').",
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
    except GYBError as exc:
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
    except GYBError as exc:
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
    except GYBError as exc:
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
    except GYBError as exc:
        raise click.ClickException(str(exc)) from exc
    ctx.console.print(f"[yellow]Deleted profile {name!r}.[/yellow]")
