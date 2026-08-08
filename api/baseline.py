"""
GET /api/baseline
-----------------
Return the ISO/IEC 27001:2022 Annex A control catalogue the engine assesses
against, plus the list of bundled demo profiles.

Used by the frontend on first load to render the control catalogue and the
sample picker before any telemetry has been submitted. The response is static
for a given deployment, so it is cached hard at the edge.
"""

import os
import sys

# See api/audit.py — Vercel does not guarantee api/ is on sys.path.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, _ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from _common import JSONHandler, get_engine, list_samples        # noqa: E402


class handler(JSONHandler):                                   # noqa: N801
    def get(self):
        engine = get_engine()

        modes = {"automated": 0, "hybrid": 0, "manual": 0}
        themes = {}
        for c in engine.controls:
            modes[c["mode"]] = modes.get(c["mode"], 0) + 1
            themes[c["theme"]] = themes.get(c["theme"], 0) + 1

        # Trim the per-control payload: the frontend needs identity and guidance,
        # not the raw check specs (those come back with an actual assessment).
        controls = [{
            "id": c["id"],
            "title": c["title"],
            "theme": c["theme"],
            "objective": c["objective"],
            "mode": c["mode"],
            "severity": c["severity"],
            "attestation": c.get("attestation"),
            "checkCount": len(c.get("checks", [])),
            "remediation": c.get("remediation", []),
        } for c in engine.controls]

        self.send_json({
            "framework": engine.baseline.get("framework"),
            "version": engine.baseline.get("version"),
            "total": len(controls),
            "modes": modes,
            "themes": themes,
            "severityWeights": engine.weights,
            "samples": list_samples(),
            "controls": controls,
        })
        return None

    def send_json(self, obj, status=200):
        import json
        body = json.dumps(obj, default=str).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", {
            "Content-Length": str(len(body)),
            "Cache-Control": "public, max-age=3600, s-maxage=86400",
        })
        self.wfile.write(body)
