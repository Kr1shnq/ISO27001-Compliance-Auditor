"""
POST /api/audit
---------------
Evaluate system configuration telemetry against the 93 ISO/IEC 27001:2022
Annex A controls and return the full assessment.

Request body (JSON), one telemetry source required:

    {
      "content":  "<raw text of an uploaded .json or .csv>",
      "filename": "ISOTelemetry_HOST_20260808.json",

      // ...or...
      "telemetry": { "identity": { "mfa_enabled": true }, ... },

      // ...or...
      "sample": "hardened_server.json",

      // optional
      "attestations": { "isms_policy_approved": true },
      "scopedOut":    ["A.8.25", "A.8.30"],
      "strict":       false
    }

Response 200:

    {
      "source": "hardened_server.json",
      "warnings": [],
      "evidence": { "identity.mfa_enabled": true, ... },
      "report": { compliance_score, coverage, counts, risk_counts,
                  themes, controls[93], roadmap[], ... }
    }

Errors return {"error": "<human readable message>"} with a 4xx/5xx status.
"""

import os
import sys

# Vercel does not reliably place the api/ directory on sys.path, so a bare
# `from _common import ...` can raise ModuleNotFoundError while the module is
# being imported — before any handler exists to catch it, which surfaces as an
# opaque platform 500. Bootstrap both api/ and the repo root explicitly.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, _ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from _common import JSONHandler, run_audit                       # noqa: E402


class handler(JSONHandler):                                   # noqa: N801
    def post(self):
        payload = self.read_json()
        report, ctx = run_audit(payload)

        result = report.to_dict()
        return {
            "source": ctx["source"],
            "warnings": ctx["warnings"],
            "meta": ctx["meta"],
            # The evidence table drives the frontend's Evidence tab and lets the
            # client re-request a PDF without re-uploading the original file.
            "evidence": report.flat,
            "report": result,
        }
