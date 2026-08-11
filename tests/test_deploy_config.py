"""
test_deploy_config.py
---------------------
Validates the Railway deployment configuration against the platform's documented
schema.

This suite exists because a bad deploy config does not fail loudly. An unknown
value is typically ignored rather than rejected, so the build succeeds, the
dashboard looks healthy, and the only symptom is an app that never becomes
reachable. These assertions encode the constraints that actually matter.

Run:  python tests/test_deploy_config.py
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAILED = []


def check(name, condition, detail=""):
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}" + (f"  -> {detail}" if detail else ""))
    if not condition:
        FAILED.append(name)


# Documented at https://docs.railway.com/config-as-code/reference
VALID_BUILDERS = {"RAILPACK", "DOCKERFILE"}
VALID_RESTART = {"ON_FAILURE", "ALWAYS", "NEVER"}

START_CMD = "streamlit run app/main.py --server.port $PORT"


print("\n=== railway.json ===")
with open(os.path.join(ROOT, "railway.json"), encoding="utf-8") as fh:
    rail = json.load(fh)

build = rail.get("build", {})
deploy = rail.get("deploy", {})

check("Builder is valid or omitted (RAILPACK is the default)",
      "builder" not in build or build["builder"] in VALID_BUILDERS,
      f"got {build.get('builder', '(omitted)')} — NIXPACKS is no longer accepted")
check("Restart policy is a documented value",
      deploy.get("restartPolicyType") in VALID_RESTART,
      str(deploy.get("restartPolicyType")))
check("Start command is present", bool(deploy.get("startCommand")))
check("Start command binds Railway's assigned port",
      "$PORT" in deploy.get("startCommand", ""),
      "hardcoding a port makes the app unreachable behind Railway's proxy")
check("Start command points at the real entrypoint",
      os.path.isfile(os.path.join(ROOT, "app", "main.py")) and
      "app/main.py" in deploy.get("startCommand", ""))
check("Healthcheck path is Streamlit's own endpoint",
      deploy.get("healthcheckPath") == "/_stcore/health",
      str(deploy.get("healthcheckPath")))


print("\n=== Procfile ===")
with open(os.path.join(ROOT, "Procfile"), encoding="utf-8") as fh:
    procfile = fh.read().strip()
check("Declares a web process", procfile.startswith("web:"), procfile)
check("Matches railway.json's start command",
      procfile[len("web:"):].strip() == deploy.get("startCommand"),
      f"Procfile: {procfile[len('web:'):].strip()!r}")


print("\n=== .streamlit/config.toml ===")
with open(os.path.join(ROOT, ".streamlit", "config.toml"), encoding="utf-8") as fh:
    cfg_text = fh.read()
cfg = dict(re.findall(r"^\s*(\w+)\s*=\s*(.+?)\s*$", cfg_text, re.M))

check("Binds 0.0.0.0, not localhost",
      cfg.get("address") == '"0.0.0.0"',
      f"{cfg.get('address')} — Railway cannot route to localhost")
check("Headless startup enabled",
      cfg.get("headless") == "true",
      "the email prompt blocks container startup otherwise")
check("Port is NOT hardcoded in the TOML",
      "port" not in cfg,
      "a TOML file cannot read $PORT; it must come from the start command")
check("Upload size is capped", cfg.get("maxUploadSize") is not None,
      f"{cfg.get('maxUploadSize')} MB")
check("XSRF protection is not disabled",
      "enableXsrfProtection" not in cfg or cfg["enableXsrfProtection"] == "true",
      "disabling CSRF protection in a security tool needs a deliberate decision")


print("\n=== Runtime prerequisites ===")
with open(os.path.join(ROOT, "requirements.txt"), encoding="utf-8") as fh:
    reqs = fh.read().lower()
for pkg in ("streamlit", "pandas", "plotly", "fpdf2"):
    check(f"requirements.txt declares {pkg}", pkg in reqs)
check("Python version pinned for the build",
      os.path.isfile(os.path.join(ROOT, ".python-version")))
check("Baseline data is committed, not generated at boot",
      os.path.isfile(os.path.join(ROOT, "data", "iso27001_baseline.json")))
check("No Vercel artefacts remain",
      not any(os.path.exists(os.path.join(ROOT, p))
              for p in ("vercel.json", ".vercelignore", "api", "public", "core")))


print("\n" + "=" * 62)
if FAILED:
    print(f"RESULT: {len(FAILED)} check(s) FAILED")
    for f in FAILED:
        print(f"   - {f}")
    sys.exit(1)
print("RESULT: deployment config is valid")
print("=" * 62)
