"""
test_api.py
-----------
Verifies the Vercel serverless endpoints (api/audit.py, api/report.py,
api/baseline.py) by running them behind the local dev server, which routes
requests exactly as Vercel does.

Checks request handling, result parity with the audit engine, attestation and
scoping behaviour, and that malformed input produces clean error envelopes
rather than stack traces.

Run:  python tests/test_api.py
"""

import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "api"))
sys.path.insert(0, os.path.join(ROOT, "tools"))

from core.audit_engine import AuditEngine       # noqa: E402
from core.ingestion import parse_bytes          # noqa: E402

FAILED = []


def check(name, condition, detail=""):
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}" + (f"  -> {detail}" if detail else ""))
    if not condition:
        FAILED.append(name)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


from http.server import ThreadingHTTPServer     # noqa: E402
import dev_server                               # noqa: E402

PORT = free_port()
BASE = f"http://127.0.0.1:{PORT}"
server = ThreadingHTTPServer(("127.0.0.1", PORT), dev_server.Router)
threading.Thread(target=server.serve_forever, daemon=True).start()
time.sleep(0.4)


def request(path, payload=None, method=None, raw=False):
    """Return (status, body). Body is parsed JSON unless raw=True."""
    url = BASE + path
    data = json.dumps(payload).encode() if payload is not None else None
    if isinstance(payload, str):                        # deliberately bad JSON
        data = payload.encode()
    req = urllib.request.Request(
        url, data=data, method=method or ("POST" if data else "GET"),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read()
            return resp.status, (body if raw else json.loads(body))
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            return exc.code, json.loads(body)
        except ValueError:
            return exc.code, {"error": body.decode("utf-8", "replace")[:200]}


# ---------------------------------------------------------------------------
print("\n=== 0. Handlers import without api/ on sys.path ===")
# Vercel does not guarantee the api/ directory is importable, so a bare
# `from _common import ...` fails at module import — before any handler exists
# to catch it, producing an opaque platform 500. Reproduce that environment
# exactly: import each handler in a subprocess whose sys.path contains neither
# api/ nor the repo root, relying only on the bootstrap inside each file.
import importlib.util                                     # noqa: E402
import subprocess                                         # noqa: E402

for mod in ("audit", "report", "baseline", "health"):
    src = (
        "import sys, os, importlib.util\n"
        # Strip everything that would make the import succeed by accident.
        f"sys.path = [p for p in sys.path if os.path.abspath(p) not in "
        f"({os.path.join(ROOT, 'api')!r}, {ROOT!r})]\n"
        "os.chdir('/')\n"                                  # cwd must not matter
        f"spec = importlib.util.spec_from_file_location('h_{mod}', "
        f"{os.path.join(ROOT, 'api', mod + '.py')!r})\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(m)\n"
        "assert hasattr(m, 'handler'), 'no handler class'\n"
        "print('OK')\n"
    )
    proc = subprocess.run([sys.executable, "-c", src], capture_output=True, text=True)
    detail = (proc.stderr.strip().splitlines() or [""])[-1][:90]
    check(f"api/{mod}.py imports in a bare interpreter",
          proc.returncode == 0 and "OK" in proc.stdout, detail)


print("\n=== 0b. GET /api/health ===")
status, h = request("/api/health")
check("Health endpoint reports healthy", status == 200 and h.get("healthy") is True,
      f"{status} " + json.dumps({k: v.get("ok") for k, v in h.get("checks", {}).items()}))
if h.get("checks"):
    check("All required files present in the bundle",
          all(h["checks"]["files_present"]["value"].values()),
          str({k: v for k, v in h["checks"]["files_present"]["value"].items() if not v}))
    check("Engine loads 93 controls",
          h["checks"]["load_engine"]["value"]["controls"] == 93)
    check("fpdf2 importable", h["checks"]["import_fpdf2"]["ok"],
          str(h["checks"]["import_fpdf2"].get("value") or
              h["checks"]["import_fpdf2"].get("error")))


print("\n=== 1. GET /api/baseline ===")
status, d = request("/api/baseline")
check("200 OK", status == 200, str(status))
check("93 controls returned", d.get("total") == 93, str(d.get("total")))
check("Mode split 20/27/46",
      d["modes"] == {"automated": 20, "hybrid": 27, "manual": 46}, str(d["modes"]))
check("Theme split 37/8/14/34",
      d["themes"] == {"Organizational": 37, "People": 8,
                      "Physical": 14, "Technological": 34}, str(d["themes"]))
check("Three samples advertised", len(d["samples"]) == 3, str(d["samples"]))
check("Controls carry remediation guidance",
      all(c["remediation"] for c in d["controls"]))
check("Raw check specs are not exposed",
      all("checks" not in c for c in d["controls"]))


print("\n=== 2. POST /api/audit — parity with the engine ===")
engine = AuditEngine()
for sample in ("hardened_server.json", "legacy_workstation.json", "mixed_endpoint.csv"):
    with open(os.path.join(ROOT, "samples", sample), "rb") as fh:
        local = engine.run(parse_bytes(fh.read(), sample)).to_dict()
    status, d = request("/api/audit", {"sample": sample})
    check(f"{sample}: 200 OK", status == 200, str(status))
    api = d["report"]
    check(f"{sample}: score matches engine",
          api["compliance_score"] == local["compliance_score"],
          f"api {api['compliance_score']} vs local {local['compliance_score']}")
    check(f"{sample}: counts match", api["counts"] == local["counts"])
    check(f"{sample}: all 93 controls", len(api["controls"]) == 93)
    check(f"{sample}: roadmap present", len(api["roadmap"]) > 0)
    check(f"{sample}: evidence returned", len(d["evidence"]) > 100,
          f"{len(d['evidence'])} keys")


print("\n=== 3. POST /api/audit — the three input shapes ===")
with open(os.path.join(ROOT, "samples", "mixed_endpoint.csv"), encoding="utf-8") as fh:
    csv_text = fh.read()
status, d = request("/api/audit", {"content": csv_text, "filename": "mixed_endpoint.csv"})
check("Raw CSV upload accepted", status == 200 and d["report"]["compliance_score"] == 46.5,
      str(d.get("report", {}).get("compliance_score")))

with open(os.path.join(ROOT, "samples", "hardened_server.json"), encoding="utf-8") as fh:
    nested = json.load(fh)
status, d = request("/api/audit", {"telemetry": nested})
check("Nested telemetry object accepted",
      status == 200 and d["report"]["compliance_score"] == 83.8,
      str(d.get("report", {}).get("compliance_score")))

status, d = request("/api/audit", {"content": json.dumps(nested), "filename": "x.json"})
check("Raw JSON upload accepted",
      status == 200 and d["report"]["compliance_score"] == 83.8)


print("\n=== 4. Attestations, scoping and strict mode ===")
status, base = request("/api/audit", {"sample": "legacy_workstation.json"})
status, att = request("/api/audit", {
    "sample": "legacy_workstation.json",
    "attestations": {"isms_policy_approved": True, "nda_in_place": True,
                     "incident_response_plan": True}})
check("Attestations reduce MANUAL count",
      att["report"]["counts"]["MANUAL"] < base["report"]["counts"]["MANUAL"],
      f"{base['report']['counts']['MANUAL']} -> {att['report']['counts']['MANUAL']}")

status, sc = request("/api/audit", {"sample": "legacy_workstation.json",
                                    "scopedOut": ["A.8.25", "A.8.30"]})
check("scopedOut yields N/A", sc["report"]["counts"]["N/A"] == 2,
      str(sc["report"]["counts"]))

status, strict = request("/api/audit", {"sample": "legacy_workstation.json", "strict": True})
check("strict lowers the score",
      strict["report"]["compliance_score"] < base["report"]["compliance_score"],
      f"{base['report']['compliance_score']} -> {strict['report']['compliance_score']}")

status, nulls = request("/api/audit", {
    "sample": "legacy_workstation.json",
    "attestations": {"isms_policy_approved": None}})
check("Null attestations are ignored, not treated as False",
      nulls["report"]["counts"] == base["report"]["counts"])

status, thin = request("/api/audit", {
    "telemetry": {"metadata": {"hostname": "MIN"}, "identity": {"mfa_enabled": True}}})
check("Thin telemetry returns a coverage warning",
      thin["report"]["coverage_warning"] is not None,
      f"coverage {thin['report']['coverage']}%")


print("\n=== 5. POST /api/report — PDF ===")
status, pdf = request("/api/report", {"sample": "hardened_server.json",
                                      "org": "Acme Corporation",
                                      "auditor": "Krishna",
                                      "scopeNote": "Automated technical assessment."},
                      raw=True)
check("200 OK", status == 200, str(status))
check("Body is a PDF", pdf[:4] == b"%PDF", repr(pdf[:8]))
check("PDF is a plausible size", len(pdf) > 20000, f"{len(pdf)/1024:.0f} KB")

status, small = request("/api/report", {"sample": "hardened_server.json",
                                        "sections": {"register": False, "roadmap": False,
                                                     "appendix": False}}, raw=True)
check("Section toggles shrink the PDF", len(small) < len(pdf),
      f"{len(small)/1024:.0f} KB vs {len(pdf)/1024:.0f} KB")


print("\n=== 6. Error handling ===")
cases = [
    ("no telemetry source", "/api/audit", {}, 400, "Provide one of"),
    ("unknown sample", "/api/audit", {"sample": "nope.json"}, 404, "Unknown sample"),
    ("path traversal blocked", "/api/audit", {"sample": "../../etc/passwd"}, 404, "Unknown sample"),
    ("non-string content", "/api/audit", {"content": 123}, 400, "must be a string"),
    ("unparseable content", "/api/audit", {"content": "@@@ not data @@@",
                                           "filename": "x.json"}, 400, ""),
    ("bad attestations type", "/api/audit", {"sample": "hardened_server.json",
                                             "attestations": "yes"}, 400, "must be a JSON object"),
    ("JSON array body", "/api/audit", "[1,2,3]", 400, "must be a JSON object"),
    ("malformed JSON", "/api/audit", "{not json", 400, "not valid JSON"),
]
for name, path, payload, want_status, want_text in cases:
    status, d = request(path, payload)
    msg = d.get("error", "") if isinstance(d, dict) else ""
    ok = status == want_status and (want_text.lower() in msg.lower() if want_text else bool(msg))
    check(name, ok, f"{status}: {msg[:70]}")

status, d = request("/api/audit", method="GET")
check("GET on a POST endpoint is rejected cleanly",
      status == 405 and "POST" in d.get("error", ""), f"{status}: {d.get('error','')[:50]}")

status, d = request("/api/baseline", {"x": 1})
check("POST on a GET endpoint is rejected cleanly", status == 405, str(status))

status, d = request("/api/nonexistent")
check("Unknown endpoint returns 404", status == 404, str(status))


print("\n=== 7. CORS preflight ===")
req = urllib.request.Request(BASE + "/api/audit", method="OPTIONS")
with urllib.request.urlopen(req, timeout=10) as resp:
    check("OPTIONS returns 204", resp.status == 204, str(resp.status))
    check("Allow-Origin header present",
          resp.headers.get("Access-Control-Allow-Origin") is not None)
    check("Allow-Methods includes POST",
          "POST" in (resp.headers.get("Access-Control-Allow-Methods") or ""))


print("\n=== 8. Static file serving ===")
status, body = request("/", raw=True)
check("Root serves the frontend", status == 200 and b"<" in body[:200], str(status))


server.shutdown()

print("\n" + "=" * 62)
if FAILED:
    print(f"RESULT: {len(FAILED)} check(s) FAILED")
    for f in FAILED:
        print(f"   - {f}")
    sys.exit(1)
print("RESULT: all API checks passed")
print("=" * 62)
