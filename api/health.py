"""
GET /api/health
---------------
Deployment self-check. Reports whether the function bundle contains everything
the audit endpoints need, and shows the exact failure if not.

Deliberately imports nothing beyond the standard library at module level, and
performs every probe inside its own try/except. If `core` is missing, `fpdf2`
failed to install, or the baseline JSON did not make it into the bundle, this
endpoint still answers and names the problem — whereas the other endpoints
would die during import and surface an opaque platform 500 with no detail.

Returns no environment variables, secrets or request data.
"""

import json
import os
import platform
import sys
import traceback
from http.server import BaseHTTPRequestHandler

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def probe(fn):
    """Run a check, returning its value or a description of how it failed."""
    try:
        return {"ok": True, "value": fn()}
    except Exception as exc:                                     # noqa: BLE001
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc().splitlines()[-6:],
        }


def check_paths():
    wanted = ["core/__init__.py", "core/audit_engine.py", "core/ingestion.py",
              "core/pdf_report.py", "data/iso27001_baseline.json",
              "samples/hardened_server.json", "api/_common.py"]
    return {p: os.path.isfile(os.path.join(ROOT, p)) for p in wanted}


def check_common():
    for p in (HERE, ROOT):
        if p not in sys.path:
            sys.path.insert(0, p)
    import _common                                               # noqa: F401
    return "api/_common.py imported"


def check_engine():
    for p in (HERE, ROOT):
        if p not in sys.path:
            sys.path.insert(0, p)
    from core.audit_engine import AuditEngine
    engine = AuditEngine()
    return {"controls": len(engine.controls),
            "baseline": engine.baseline.get("version")}


def check_audit():
    for p in (HERE, ROOT):
        if p not in sys.path:
            sys.path.insert(0, p)
    from core.audit_engine import AuditEngine
    from core.ingestion import parse_bytes
    with open(os.path.join(ROOT, "samples", "hardened_server.json"), "rb") as fh:
        report = AuditEngine().run(parse_bytes(fh.read(), "hardened_server.json"))
    return {"score": report.compliance_score, "assessed": len(report.assessed)}


def check_fpdf():
    import fpdf
    return f"fpdf2 {getattr(fpdf, '__version__', 'unknown')}"


class handler(BaseHTTPRequestHandler):                           # noqa: N801
    def do_GET(self):                                            # noqa: N802
        checks = {
            "files_present": probe(check_paths),
            "import_common": probe(check_common),
            "load_engine": probe(check_engine),
            "run_audit": probe(check_audit),
            "import_fpdf2": probe(check_fpdf),
        }
        healthy = all(c["ok"] for c in checks.values()) and \
            all(checks["files_present"]["value"].values()) \
            if checks["files_present"]["ok"] else False

        body = json.dumps({
            "healthy": healthy,
            "runtime": {
                "python": platform.python_version(),
                "cwd": os.getcwd(),
                "handler_dir": HERE,
                "project_root": ROOT,
                "root_listing": sorted(os.listdir(ROOT))[:40],
                "sys_path_head": sys.path[:8],
            },
            "checks": checks,
        }, indent=2, default=str).encode("utf-8")

        self.send_response(200 if healthy else 503)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return
