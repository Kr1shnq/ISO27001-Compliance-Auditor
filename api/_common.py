"""
_common.py
----------
Shared helpers for the Vercel Python serverless functions.

Vercel discovers one handler per file under `api/`. Files whose name starts with
an underscore are treated as private modules rather than routes, so this one is
importable by the handlers without becoming an endpoint itself.

Every handler subclasses `JSONHandler`, which provides:
  * repo-root import bootstrap so `core` resolves inside the function bundle
  * request body reading with a hard size cap
  * JSON and binary responses with consistent headers
  * uniform error envelopes, so the frontend can always read `.error`
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from http.server import BaseHTTPRequestHandler

# The function bundle preserves the repo layout (see includeFiles in
# vercel.json), so core/ sits one level above this file.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Vercel's request body limit for functions is 4.5 MB. Refuse anything close to
# it with a clear message rather than letting the platform truncate the payload.
MAX_BODY_BYTES = 4 * 1024 * 1024

ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")


class ApiError(Exception):
    """An error whose message is safe to show the user."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status
        self.message = message


class JSONHandler(BaseHTTPRequestHandler):
    """Base handler. Subclasses implement `post(payload) -> dict`."""

    # -- plumbing ---------------------------------------------------------
    def _headers(self, status: int, content_type: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def send_json(self, obj, status: int = 200):
        body = json.dumps(obj, default=str).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8",
                      {"Content-Length": str(len(body))})
        self.wfile.write(body)

    def send_binary(self, data: bytes, content_type: str, filename: str):
        self._headers(200, content_type, {
            "Content-Length": str(len(data)),
            "Content-Disposition": f'attachment; filename="{filename}"',
        })
        self.wfile.write(data)

    def send_error_json(self, message: str, status: int = 400):
        self.send_json({"error": message}, status=status)

    def read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            raise ApiError("Content-Length header was missing or malformed.")
        if length <= 0:
            raise ApiError("Request body was empty.")
        if length > MAX_BODY_BYTES:
            raise ApiError(
                f"Payload is {length / 1024 / 1024:.1f} MB. The limit is "
                f"{MAX_BODY_BYTES / 1024 / 1024:.0f} MB — a telemetry report should be "
                f"far smaller than this, so check you uploaded the right file.", 413)
        return self.rfile.read(length)

    def read_json(self) -> dict:
        raw = self.read_body()
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ApiError(f"Request body was not valid JSON: {exc}")
        if not isinstance(payload, dict):
            raise ApiError("Request body must be a JSON object.")
        return payload

    # -- HTTP verbs -------------------------------------------------------
    def do_OPTIONS(self):                                    # noqa: N802
        self._headers(204, "text/plain", {"Access-Control-Max-Age": "86400"})

    def do_GET(self):                                        # noqa: N802
        self._dispatch(self.get)

    def do_POST(self):                                       # noqa: N802
        self._dispatch(self.post)

    def _dispatch(self, fn):
        try:
            result = fn()
            if result is not None:
                self.send_json(result)
        except ApiError as exc:
            self.send_error_json(exc.message, exc.status)
        except Exception as exc:                             # noqa: BLE001
            # Log the trace to the function output for debugging, but never leak
            # internals to the client.
            traceback.print_exc()
            self.send_error_json(
                f"The server could not complete the request: "
                f"{type(exc).__name__}. Check the file format and try again.", 500)

    # -- overridable ------------------------------------------------------
    def get(self):
        raise ApiError("This endpoint expects a POST request.", 405)

    def post(self):
        raise ApiError("This endpoint expects a GET request.", 405)

    def log_message(self, fmt, *args):
        """Quieten BaseHTTPRequestHandler's stderr access log."""
        return


# ---------------------------------------------------------------------------
# Shared engine instance
# ---------------------------------------------------------------------------
_ENGINE = None


def get_engine():
    """Load the audit engine once and reuse it across warm invocations."""
    global _ENGINE
    if _ENGINE is None:
        from core.audit_engine import AuditEngine
        _ENGINE = AuditEngine()
    return _ENGINE


def run_audit(payload: dict):
    """Shared request handling for /api/audit and /api/report.

    Accepts either already-parsed telemetry or a raw uploaded file:

        {"telemetry": {...nested or flat...}}          preferred
        {"content": "<file text>", "filename": "x.csv"} raw upload
        {"sample": "hardened_server.json"}              bundled demo profile

    plus optional {"attestations": {...}, "scopedOut": [...], "strict": bool}.
    """
    from core.ingestion import parse_bytes, flatten, validate

    telemetry = payload.get("telemetry")
    content = payload.get("content")
    sample = payload.get("sample")

    def _parse(raw: bytes, name: str):
        """Parse an uploaded file, turning any failure into a usable message.

        The ingestion layer raises ValueError/JSONDecodeError for malformed
        input. Those are the user's problem, not a server fault, so they must
        surface as a 400 explaining what to fix rather than a bare 500.
        """
        try:
            return parse_bytes(raw, name)
        except ApiError:
            raise
        except Exception as exc:                             # noqa: BLE001
            raise ApiError(
                f"Could not read '{name}': {exc} "
                f"Supply JSON, or CSV with either key/value columns or a header "
                f"row of dotted keys. The collector's own output always works.")

    if content is not None:
        filename = payload.get("filename") or "upload.json"
        if not isinstance(content, str):
            raise ApiError("'content' must be a string containing the file text.")
        flat = _parse(content.encode("utf-8"), filename)
        source = filename
    elif sample is not None:
        flat = _parse(load_sample(sample), sample)
        source = sample
    elif telemetry is not None:
        if not isinstance(telemetry, dict):
            raise ApiError("'telemetry' must be a JSON object.")
        flat = flatten(telemetry)
        source = payload.get("filename") or "telemetry.json"
    else:
        raise ApiError("Provide one of 'telemetry', 'content' or 'sample'.")

    if not flat:
        raise ApiError("No parameters could be parsed from the supplied data.")

    attestations = payload.get("attestations") or {}
    if not isinstance(attestations, dict):
        raise ApiError("'attestations' must be a JSON object.")
    attestations = {k: v for k, v in attestations.items() if v is not None}

    scoped_out = set(payload.get("scopedOut") or [])
    strict = bool(payload.get("strict"))

    report = get_engine().run(flat, attestations=attestations,
                              scoped_out=scoped_out, include_manual_as_fail=strict)
    ok, warnings, meta = validate(flat)
    return report, {"source": source, "warnings": warnings, "meta": meta}


# ---------------------------------------------------------------------------
# Bundled sample profiles
# ---------------------------------------------------------------------------
SAMPLE_DIR = os.path.join(ROOT, "samples")
ALLOWED_SAMPLES = {
    "hardened_server.json", "legacy_workstation.json", "mixed_endpoint.csv",
}


def list_samples():
    return sorted(ALLOWED_SAMPLES)


def load_sample(name: str) -> bytes:
    # Allow-list rather than path sanitisation: the set of demo profiles is
    # fixed and known, so there is no reason to accept an arbitrary path.
    if name not in ALLOWED_SAMPLES:
        raise ApiError(f"Unknown sample '{name}'. "
                       f"Available: {', '.join(sorted(ALLOWED_SAMPLES))}.", 404)
    path = os.path.join(SAMPLE_DIR, name)
    if not os.path.isfile(path):
        raise ApiError(f"Sample '{name}' is not present in this deployment.", 500)
    with open(path, "rb") as fh:
        return fh.read()
