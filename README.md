# ISO 27001 Compliance Auditor

Automated gap analysis of Windows system configuration against all **93 ISO/IEC 27001:2022
Annex A controls**, with real-time compliance visibility and an actionable remediation roadmap.

**Live demo:** https://web-production-f71a4.up.railway.app

No Windows machine needed — load one of the three bundled demonstration profiles from the
sidebar to see a full assessment.

## Quick start

```bash
pip install -r requirements.txt
streamlit run app/main.py          # or: ./run.sh
```

Then load one of the bundled samples from the sidebar to explore, or collect real telemetry:

```powershell
# On the target Windows host, in an elevated PowerShell session
.\collector\Collect-ISOTelemetry.ps1 -OutputPath C:\Audit -IncludeAttestations
```

Upload the resulting `ISOTelemetry_<HOST>_<timestamp>.json` in the web app.

## Deploying to Railway

Railway runs persistent containers, which is what Streamlit needs — it holds session
state in memory and keeps a WebSocket open for the life of the session.

1. At [railway.com](https://railway.com), open the dashboard and choose
   **New Project → Deploy from GitHub repo**, then pick this repository.
2. Choose **Deploy Now**. Railpack detects Python from `requirements.txt` and installs it;
   `railway.json` supplies the start command and health check. No environment variables
   are required.
3. Once the build succeeds, open the service → **Settings → Networking → Generate Domain**.

The configuration that matters:

| File | Why |
|---|---|
| `railway.json` | Start command, `/_stcore/health` health check, restart policy. No `builder` key — Railpack is the default; `NIXPACKS` is no longer a valid value. |
| `Procfile` | Same start command, for any Procfile-based host |
| `.streamlit/config.toml` | Binds `0.0.0.0`, headless startup, 10 MB upload cap, theme |
| `.python-version` | Pins Python 3.12 for the build |

Two settings are load-bearing rather than cosmetic. Streamlit binds `localhost:8501` by
default, which Railway cannot route to, so `address = "0.0.0.0"` is set in
`config.toml` and the port comes from `$PORT` on the command line — a TOML file cannot
read an environment variable. And `headless = true` skips the interactive "enter your
email" prompt, which would otherwise block startup in a container.

**If file uploads fail** with an XSRF error, that is the known interaction between
Streamlit's CSRF token and a reverse proxy. Confirm by temporarily appending
`--server.enableXsrfProtection false` to the start command — but treat that as a
diagnosis, not a fix, since it disables a real security control in a security tool.

Verify the config before deploying:

```bash
python tests/test_deploy_config.py
```

## Layout

| Path | Purpose |
|---|---|
| `app/main.py` | Streamlit UI — dashboard, register, roadmap, attestations, export |
| `app/ingestion.py` | JSON/CSV parsing, type coercion, flattening, validation |
| `app/audit_engine.py` | Control evaluation, risk assignment, weighted scoring, roadmap |
| `app/pdf_report.py` | FPDF audit report generation |
| `data/build_baseline.py` | Generator for the 93-control Annex A baseline |
| `data/iso27001_baseline.json` | The machine-readable baseline the engine consumes |
| `collector/Collect-ISOTelemetry.ps1` | Read-only Windows telemetry collector |
| `samples/` | Three demo profiles (hardened, legacy, mixed) |
| `tests/test_engine.py` | End-to-end verification suite |
| `tests/test_deploy_config.py` | Validates the Railway config against the documented schema |
| `tools/refresh_samples.py` | Regenerates every committed artefact |
| `docs/` | User guide PDF and sample audit reports |
| `railway.json`, `Procfile`, `.streamlit/config.toml` | Deployment configuration |

## How scoring works

Each control is evaluated to `PASS` / `PARTIAL` / `FAIL` / `MANUAL` / `NO_DATA` / `N/A`.

```
score = Σ(weight × credit) / Σ(weight)      credit: PASS 1.0, PARTIAL 0.5, FAIL 0.0
                                            weight: High 5, Medium 3, Low 1
```

`MANUAL` and `NO_DATA` controls sit outside the denominator unless **Strict mode** is on.
The app also reports **assessment coverage** — what fraction of the 93 controls produced a
real verdict — so a thin telemetry file cannot masquerade as a clean audit.

## Assessment modes

| Mode | Count | How it is decided |
|---|---|---|
| Automated | 20 | Purely from telemetry |
| Hybrid | 27 | Telemetry **and** auditor attestation |
| Manual | 46 | Auditor attestation only (procedural controls) |

## Tests

```bash
python tests/test_engine.py          # engine, ingestion, scoring, roadmap, PDF
python tests/test_deploy_config.py   # Railway config against the documented schema
```

Covers baseline integrity, all comparison operators, ingestion and type coercion,
PowerShell 5.1 serialisation quirks, the three sample profiles, control-level
correctness, attestations and scoping, the coverage guard, roadmap ordering,
scoring arithmetic and PDF generation.

## Notes and limitations

- The collector is strictly read-only and makes no outbound connection.
- Without elevation, BitLocker / audit policy / Defender / firewall probes return no
  data and the affected controls report `NO_DATA` rather than a false pass.
- MFA is inferred from installed credential providers; confirm it by attestation if you
  use an MFA product the heuristic cannot see.
- Backup encryption, off-site copies and restore testing are not discoverable from a
  local host — record them as attestations.
- This is a technical configuration assessment. It supports, but does not replace, a
  full ISMS certification audit.
