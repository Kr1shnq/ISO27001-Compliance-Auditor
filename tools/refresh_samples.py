"""
refresh_samples.py
------------------
Regenerates every committed artefact from source:

    samples/*.json, samples/*.csv          demo telemetry profiles
    data/iso27001_baseline.json            the 93-control Annex A baseline
    docs/sample_audit_*.pdf                example audit reports
    docs/ISO27001_..._Guide.pdf            the overview and user guide

Run after changing the baseline, the sample profiles or the report layout:

    python tools/refresh_samples.py

Kept separate from the test suite deliberately: PDFs embed a creation
timestamp, so regenerating them on every test run would leave the working
tree permanently dirty.
"""

import os
import runpy
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.ingestion import parse_bytes       # noqa: E402
from core.audit_engine import AuditEngine    # noqa: E402
from core.pdf_report import build_pdf        # noqa: E402


def run(script):
    path = os.path.join(ROOT, script)
    print(f"-> {script}")
    runpy.run_path(path, run_name="__main__")


def main():
    run("data/build_baseline.py")
    run("samples/make_samples.py")

    engine = AuditEngine()
    for sample, label in (("hardened_server.json", "hardened"),
                          ("legacy_workstation.json", "legacy")):
        with open(os.path.join(ROOT, "samples", sample), "rb") as fh:
            report = engine.run(parse_bytes(fh.read(), sample))
        pdf = build_pdf(
            report,
            org="Acme Corporation",
            auditor="Information Security Team",
            scope_note="Automated point-in-time technical assessment of a single "
                       "host, produced from the bundled demonstration telemetry.")
        out = os.path.join(ROOT, "docs", f"sample_audit_{label}.pdf")
        with open(out, "wb") as fh:
            fh.write(pdf)
        print(f"-> docs/sample_audit_{label}.pdf  "
              f"({len(pdf)/1024:.0f} KB, score {report.compliance_score}%)")

    run("docs/build_guide.py")

    print("\nVerifying...")
    rc = subprocess.call([sys.executable, os.path.join(ROOT, "tests", "test_engine.py")],
                         stdout=subprocess.DEVNULL)
    print("Test suite:", "PASSED" if rc == 0 else f"FAILED (exit {rc})")
    return rc


if __name__ == "__main__":
    sys.exit(main())
