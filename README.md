# Got Your Back (`gyb`) — GYB 2.0

**Got Your Back (`gyb`)** is a fast, modular command-line email backup, restore, and migration tool built on Python 3.11+.

## Highlights

- **Verb-First CLI**: Clean `click` interface (`gyb backup`, `gyb restore`, `gyb migrate`, `gyb retry`, `gyb report`, `gyb auth`) where local disk is treated as a standard `Source` and `Sink` alongside cloud providers.
- **Modular Source & Sink Architecture**:
  - **Sources**: Gmail API (`gmail://<email>`), Local GYB Archive (`local://<path>` with `msg-db.sqlite` + `.eml` files), and `mbox` (`mbox://<path>`, including Google Takeout and Google Vault exports).
  - **Sinks**: Gmail API (`gmail://<email>`), Local GYB Archive (`local://<path>`), and Google Groups (`groups://<group-email>` via Groups Migration API).
  - Provider quirks are strictly isolated inside `src/gyb/modules/<provider>/` — core pipeline and capability negotiation (`src/gyb/core/`) contain zero provider-specific logic.
- **Official Google Discovery Client + HTTP/2 Stream Multiplexing**: Uses `google-api-python-client` (`MediaIoBaseUpload` simple & chunked resumable uploads, Discovery schema validation, and structured `HttpError` parsing) patched over [`modern-httplib2`](https://github.com/GAM-team/modern-httplib2) HTTP/2 stream multiplexing — eliminating `/batch` endpoints in favor of concurrent HTTP/2 streams regulated by an error-driven AIMD controller (`AdaptiveStreamController`) with global coordinated exponential backoff across worker threads.
- **Mandatory DPoP Proof-of-Possession & ADC**: Uses [`google-auth` (`dpop-oauthlib`)](https://github.com/jay0lee/google-cloud-python/tree/dpop-oauthlib/packages/google-auth) and OS-scoped hardware signers from [`dpop-signers`](https://github.com/jay0lee/dpop-signers) (Software P-256, macOS Secure Enclave, Windows TPM/CNG, Linux TPM 2.0, Google ECP, YubiKey PIV, FIDO2 `previewSign`), plus Google Application Default Credentials (ADC) for Service Accounts, Domain-Wide Delegation, GCE, and Workload Identity Federation.
- **SQLite Audit Tracking & Rich Reporting**: Persistent job and per-message tracking with `gyb retry <job-id>` and `gyb report` (Rich console tables, CSV, and JSON exports).

## Quick Examples

```bash
# Authenticate an end-user profile with DPoP proof-of-possession
gyb auth setup-oauth --profile personal --client-secrets client_secrets.json

# Configure an ADC / Domain-Wide Delegation profile
gyb auth setup-adc --profile workspace-dwd --subject user@domain.com

# Backup Gmail to local native GYB folder
gyb backup user@domain.com ./GYB-GMail-Backup --profile workspace-dwd --search "newer_than:30d"

# Restore a Google Takeout or Vault mbox to Gmail with a label prefix
gyb restore ./Takeout/Mail/All\ mail.mbox user@domain.com --profile workspace-dwd --label-prefix Restored

# Archive messages into Google Groups
gyb migrate local://./GYB-GMail-Backup groups://archive@domain.com --dest-profile workspace-dwd

# Inspect job status / failures and retry failed messages
gyb report
gyb retry <job-id>
```

## Development

> **Windows Note:** Enable Git long paths (`git config --global core.longpaths true`) before syncing Git dependencies.

```bash
uv sync --dev
uv run ruff check src tests
uv run mypy
uv run pytest tests/unit --cov=gyb --cov-branch --cov-report=term-missing --cov-fail-under=100
```
