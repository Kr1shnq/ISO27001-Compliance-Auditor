"""
core
====
Framework-agnostic heart of the ISO 27001 Compliance Auditor.

Nothing in this package imports Streamlit, pandas or plotly. It depends only on
the Python standard library, plus fpdf2 for `pdf_report`. That keeps it usable
from three places without duplication:

    app/    the Streamlit application (local use)
    api/    Vercel Python serverless functions (hosted use)
    tests/  the verification suite

Public surface:

    from core import AuditEngine, parse_bytes, validate, build_pdf
"""

from .ingestion import parse_bytes, parse_json, parse_csv, validate, flatten, unflatten, coerce
from .audit_engine import (AuditEngine, AuditReport, ControlResult, CheckResult,
                           evaluate_op, DEFAULT_BASELINE,
                           PASS, PARTIAL, FAIL, MANUAL, NO_DATA, NA)

__all__ = [
    "AuditEngine", "AuditReport", "ControlResult", "CheckResult",
    "evaluate_op", "DEFAULT_BASELINE",
    "PASS", "PARTIAL", "FAIL", "MANUAL", "NO_DATA", "NA",
    "parse_bytes", "parse_json", "parse_csv", "validate",
    "flatten", "unflatten", "coerce",
]

__version__ = "1.0.0"


def build_pdf(*args, **kwargs):
    """Lazy re-export of the PDF builder.

    Imported on demand so that consumers which only need the audit engine
    (the /api/audit function, for instance) never pay for fpdf2.
    """
    from .pdf_report import build_pdf as _build_pdf
    return _build_pdf(*args, **kwargs)
