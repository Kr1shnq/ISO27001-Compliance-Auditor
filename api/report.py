"""
POST /api/report
----------------
Re-run the audit and return a management-ready PDF audit report.

The audit is re-run server-side from the supplied telemetry rather than trusting
a client-submitted result object — the PDF is a formal deliverable, so its
contents must come from the engine, not from whatever the browser posts back.

Request body (JSON): everything /api/audit accepts, plus:

    {
      "org":       "Acme Corporation",
      "auditor":   "Information Security Team",
      "scopeNote": "...",
      "sections":  { "register": true, "roadmap": true, "appendix": true }
    }

Response 200: application/pdf as a file attachment.
"""

import os
import re
import sys

# See api/audit.py — Vercel does not guarantee api/ is on sys.path.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, _ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from _common import JSONHandler, run_audit                       # noqa: E402


def safe_filename(host: str) -> str:
    """Build a download filename that is safe on every OS."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(host or "host")).strip("._-")
    return f"ISO27001_Audit_{cleaned or 'host'}.pdf"


class handler(JSONHandler):                                   # noqa: N801
    def post(self):
        payload = self.read_json()
        report, _ctx = run_audit(payload)

        sections = payload.get("sections") or {}
        # Imported here rather than at module scope so a failure to build the
        # PDF cannot take down /api/audit, and so fpdf2 is only loaded when a
        # report is actually requested.
        from core.pdf_report import build_pdf

        pdf = build_pdf(
            report,
            org=str(payload.get("org") or "Organisation")[:120],
            auditor=str(payload.get("auditor") or "Information Security")[:120],
            scope_note=str(payload.get("scopeNote") or "")[:2000],
            include_register=sections.get("register", True),
            include_roadmap=sections.get("roadmap", True),
            include_appendix=sections.get("appendix", True),
        )

        host = report.flat.get("metadata.hostname", "host")
        self.send_binary(pdf, "application/pdf", safe_filename(host))
        return None            # response already written
