# Got Your Back (`ngyb`)

`ngyb` is the next-generation rewrite of **Got Your Back (GYB)** — a fast, modular command-line email backup, restore, and migration tool built on Python 3.11+.

## Highlights

- **Verb-First CLI**: Clean `click` interface (`backup`, `restore`, `migrate`, `retry`, `report`, `auth`) where local disk is treated as a standard source/sink alongside cloud providers.
- **Modular Source & Sink Architecture**:
  - **Sources**: Gmail API, Local GYB Archive (`msg-db.sqlite` + `.eml`), and `mbox` (including Google Takeout and Google Vault exports).
  - **Sinks**: Gmail API, Local GYB Archive, and Google Groups (Groups Migration API).
  - Provider quirks are strictly isolated inside `src/ngyb/modules/<provider>/`.
- **HTTP/2 Stream Multiplexing & AIMD Dynamic Scaling**: Powered by [`modern-httplib2`](https://github.com/GAM-team/modern-httplib2) — eliminates Google `/batch` endpoints in favor of concurrent HTTP/2 streams that dynamically scale up and coordinate global exponential backoff across worker threads when throttled.
- **Mandatory DPoP Proof-of-Possession**: Uses [`google-auth` (`dpop-oauthlib`)](https://github.com/jay0lee/google-cloud-python/tree/dpop-oauthlib/packages/google-auth) and OS-scoped hardware signers from [`dpop-signers`](https://github.com/jay0lee/dpop-signers) (Software P-256, macOS Secure Enclave, Windows TPM/CNG, Linux TPM 2.0, Google ECP, YubiKey PIV, FIDO2 `previewSign`), plus Google Application Default Credentials (ADC) for Service Accounts, Domain-Wide Delegation, GCE, and Workload Identity Federation.
- **SQLite Audit Tracking & Rich Reporting**: Persistent job and per-message tracking with `ngyb retry <job-id>` and `ngyb report` (Rich console tables, CSV, and JSON exports).

## Development

```bash
uv sync --dev
uv run pytest tests/unit --cov=ngyb --cov-branch --cov-report=term-missing --cov-fail-under=100
```
