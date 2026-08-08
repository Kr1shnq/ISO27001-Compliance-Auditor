# ISO 27001 Compliance Auditor

Automated gap analysis of Windows system configuration against all **93 ISO/IEC 27001:2022
Annex A controls**, with real-time compliance visibility, a prioritised remediation roadmap
and a management-ready PDF audit report.

Two interfaces, one engine:

| Interface | Where it runs | Use it for |
|---|---|---|
| **Web app** (`public/` + `api/`) | Vercel, or any static host + Python functions | The hosted, shareable version |
| **Streamlit app** (`app/`) | Locally | Working through an audit on your own machine |

Both call the same `core/` engine, so a given telemetry file always produces the same
verdict regardless of how it is submitted — the test suite asserts that parity.

## Quick start

**Web app, locally**

```bash
pip install -r requirements.txt
python tools/dev_server.py          # http://localhost:3000
```

`dev_server.py` routes requests exactly as Vercel does — `/api/<name>` to the handler in
`api/<name>.py`, everything else to `public/`.

**Streamlit app**

```bash
pip install -r requirements-streamlit.txt
streamlit run app/dashboard.py      # or: ./run.sh
```

**Collect real telemetry**

```powershell
# On the target Windows host, in an elevated PowerShell session
.\collector\Collect-ISOTelemetry.ps1 -OutputPath C:\Audit -IncludeAttestations
```

Upload the resulting `ISOTelemetry_<HOST>_<timestamp>.json`. Or load one of the three
bundled demonstration profiles to explore without a Windows machine.

## Deploying to Vercel

```bash
npm i -g vercel
vercel            # preview deployment
vercel --prod     # production
```

Or import the repository at [vercel.com/new](https://vercel.com/new) — no build step, no
environment variables, no configuration beyond the committed `vercel.json`.

Notes on how it fits the platform:

- The audit engine is pure standard library; `fpdf2` (~2 MB) is the only runtime
  dependency, so the whole function bundle is under 3 MB against a 250 MB limit.
- Streamlit, pandas and plotly live in `requirements-streamlit.txt`, never in
  `requirements.txt`, so they can never be pulled into a serverless function.
- `.vercelignore` excludes `app/`, keeping Vercel's Python entrypoint detection away from
  the Streamlit application entirely.
- Python version is pinned in `.python-version`.

### Troubleshooting a deployment

Visit `/api/health` on the deployed URL. It imports nothing at module level and
probes each dependency separately, so it answers even when the other endpoints
cannot start, and names the specific failure:

```json
{ "healthy": true,
  "checks": { "files_present": {...}, "import_common": {...},
              "load_engine": {...}, "run_audit": {...}, "import_fpdf2": {...} } }
```

If the frontend shows *"Could not reach the audit service"*, that endpoint will say why.

**Streamlit cannot be hosted on Vercel.** It needs a persistent stateful server process
holding session state in memory; Vercel runs functions per request. That is why the web
interface exists as a separate frontend over a stateless API rather than as a port of the
Streamlit app.

## Architecture

```
 Collect-ISOTelemetry.ps1      read-only Windows inventory -> JSON / CSV
            |
            v
 core/ingestion.py             parse, coerce types, flatten to dotted keys
            |
            v
 core/audit_engine.py          evaluate 93 controls, assign risk, build roadmap
            |
      +-----+-----+
      v           v
 api/*.py    app/dashboard.py  serverless functions | Streamlit UI
      |           |
      v           v
 public/*    core/pdf_report.py  browser frontend | PDF audit report
```

### API

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/baseline` | GET | Control catalogue and sample list. Cached at the edge. |
| `/api/audit` | POST | Telemetry in, full assessment out. |
| `/api/report` | POST | Telemetry in, PDF audit report out. |
| `/api/health` | GET | Deployment self-check — see below. |

`/api/audit` accepts a raw uploaded file (`content` + `filename`), an already-parsed
`telemetry` object, or a bundled `sample`; plus optional `attestations`, `scopedOut` and
`strict`. `/api/report` re-runs the audit server-side rather than trusting a
client-submitted result object — the PDF is a formal deliverable, so its contents come
from the engine.

## Layout

| Path | Purpose |
|---|---|
| `core/` | The engine: ingestion, audit, PDF. No Streamlit, pandas or plotly. |
| `api/` | Vercel Python serverless functions |
| `public/` | Frontend — no build step, Chart.js from CDN |
| `app/dashboard.py` | Streamlit interface |
| `data/build_baseline.py` | Generator for the 93-control Annex A baseline |
| `data/iso27001_baseline.json` | The machine-readable baseline the engine consumes |
| `collector/Collect-ISOTelemetry.ps1` | Read-only Windows telemetry collector |
| `samples/` | Three demo profiles (hardened, legacy, mixed) |
| `tests/` | Engine, API and frontend suites |
| `tools/` | Dev server and artefact regeneration |
| `docs/` | User guide PDF and example audit reports |

## How scoring works

Each control resolves to `PASS` / `PARTIAL` / `FAIL` / `MANUAL` / `NO_DATA` / `N/A`.

```
score = Σ(weight × credit) / Σ(weight)      credit: PASS 1.0, PARTIAL 0.5, FAIL 0.0
                                            weight: High 5, Medium 3, Low 1
```

`MANUAL` and `NO_DATA` sit outside the denominator unless **strict mode** is on. The app
also reports **assessment coverage** — what fraction of the 93 controls produced a real
verdict — so a thin telemetry file cannot masquerade as a clean audit.

| Mode | Count | How the verdict is reached |
|---|---|---|
| Automated | 20 | Purely from telemetry |
| Hybrid | 27 | Telemetry **and** auditor attestation |
| Manual | 46 | Attestation only (procedural controls) |

## Tests

```bash
python tests/run_all.py         # everything
python tests/test_engine.py     # engine, ingestion, scoring, roadmap, PDF
python tests/test_api.py        # the three serverless endpoints
python tests/test_frontend.py   # the browser app in jsdom (needs: npm install jsdom)
```

Covers baseline integrity, every comparison operator, type coercion, PowerShell 5.1
serialisation quirks, the three sample profiles, control-level correctness, attestations
and scoping, the coverage guard, roadmap ordering, scoring arithmetic, API error
envelopes, and the frontend's full interaction path including PDF export.

`tools/refresh_samples.py` regenerates every committed artefact (baseline, samples,
example reports, user guide) and verifies the result.

## Notes and limitations

- The collector is strictly read-only and makes no outbound connection.
- Without elevation, BitLocker / audit policy / Defender / firewall probes return no data
  and the affected controls report `NO_DATA` rather than a false pass.
- MFA, DLP, EDR and backup products are detected by service names and registry markers.
  Anything the heuristic does not recognise reads as absent — confirm by attestation.
- Backup encryption, off-site copies and restore testing are not discoverable from a local
  host; record them as attestations.
- Telemetry is processed in memory and never stored. Uploads are capped at 4 MB.
- This is a technical configuration assessment of one host at a point in time. It supports,
  but does not replace, a full ISMS certification audit — ISO 27001 clauses 4–10 cover a
  management system that no registry key can measure.

## Licence

MIT — see [LICENSE](LICENSE).
