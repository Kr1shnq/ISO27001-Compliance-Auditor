"""
audit_engine.py
---------------
Logic-driven audit engine for the ISO 27001 Compliance Auditor.

Cross-references flattened telemetry against the ISO/IEC 27001:2022 Annex A
baseline, produces a per-control result, assigns a risk level, and builds a
prioritised remediation roadmap.

Result statuses
---------------
PASS        every check satisfied
PARTIAL     some but not all checks satisfied
FAIL        no check satisfied (or the single check failed)
MANUAL      control requires human attestation and none was supplied
NO_DATA     telemetry did not include any of the fields the control needs
N/A         the control was explicitly scoped out by the auditor

Scoring
-------
Weighted compliance score:
    score = sum(weight * credit) / sum(weight)  over all assessed controls
    credit = 1.0 (PASS) | 0.5 (PARTIAL) | 0.0 (FAIL)
    weight = severity_weights[severity]   (High 5, Medium 3, Low 1)
MANUAL / NO_DATA / N/A controls are excluded from the denominator by default;
`include_manual_as_fail=True` counts unanswered manual controls as failures,
which is the conservative posture a certification auditor would take.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"
MANUAL, NO_DATA, NA = "MANUAL", "NO_DATA", "N/A"

STATUS_ORDER = [FAIL, PARTIAL, NO_DATA, MANUAL, PASS, NA]
RISK_ORDER = {"High": 0, "Medium": 1, "Low": 2, "None": 3}

DEFAULT_BASELINE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "iso27001_baseline.json")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    label: str
    field: str
    op: str
    expected: Any
    observed: Any
    passed: Optional[bool]      # None => no data
    detail: str = ""


@dataclass
class ControlResult:
    id: str
    title: str
    theme: str
    objective: str
    mode: str
    severity: str
    status: str
    risk: str
    score: float
    checks: List[CheckResult] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    evidence: str = ""
    attestation: Optional[str] = None

    def to_row(self) -> dict:
        return {
            "Control": self.id,
            "Title": self.title,
            "Theme": self.theme,
            "Mode": self.mode.capitalize(),
            "Status": self.status,
            "Risk": self.risk,
            "Severity": self.severity,
            "Score": self.score,
            "Checks Passed": f"{sum(1 for c in self.checks if c.passed)}/{len(self.checks)}"
            if self.checks else "-",
            "Evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------

def _as_list(v):
    """Normalise a value for the len_* operators.

    Windows PowerShell 5.1 serialises an empty array as an empty string, so ""
    must be read as an empty collection rather than a one-element list — the
    difference between 'no unauthorised software' and 'one unnamed finding'.
    """
    if v is None:
        return None
    if isinstance(v, str) and v.strip() == "":
        return []
    return v if isinstance(v, list) else [v]


def evaluate_op(op: str, observed: Any, expected: Any) -> Optional[bool]:
    """Return True/False, or None when the observation is unusable."""
    try:
        if op in ("truthy", "falsy"):
            if observed is None:
                return None
            if isinstance(observed, str):
                obs = observed.strip().lower() not in (
                    "false", "no", "0", "off", "disabled", "", "none")
            else:
                obs = bool(observed)
            return obs if op == "truthy" else (not obs)

        if observed is None:
            return None

        if op == "eq":
            return observed == expected
        if op == "ne":
            return observed != expected
        if op in ("gt", "gte", "lt", "lte"):
            o, e = float(observed), float(expected)
            return {"gt": o > e, "gte": o >= e, "lt": o < e, "lte": o <= e}[op]
        if op == "in":
            exp = _as_list(expected) or []
            if isinstance(observed, str):
                return any(str(x).lower() == observed.lower() for x in exp)
            return observed in exp
        if op == "not_in":
            exp = _as_list(expected) or []
            if isinstance(observed, str):
                return not any(str(x).lower() == observed.lower() for x in exp)
            return observed not in exp
        if op == "contains":
            if isinstance(observed, list):
                return any(str(expected).lower() == str(x).lower() for x in observed)
            return str(expected).lower() in str(observed).lower()
        if op == "not_contains":
            if isinstance(observed, list):
                return not any(str(expected).lower() == str(x).lower() for x in observed)
            return str(expected).lower() not in str(observed).lower()
        if op in ("len_eq", "len_lte", "len_gte"):
            n = len(_as_list(observed) or [])
            e = int(expected)
            return {"len_eq": n == e, "len_lte": n <= e, "len_gte": n >= e}[op]
        if op == "non_empty":
            if isinstance(observed, (list, dict, str)):
                return len(observed) > 0
            return observed is not None
    except (TypeError, ValueError):
        return None
    raise ValueError(f"Unknown operator: {op}")


def _fmt(v: Any) -> str:
    if v is None:
        return "not collected"
    if isinstance(v, bool):
        return "Yes" if v else "No"
    if isinstance(v, list):
        return "none" if not v else ", ".join(str(x) for x in v[:6]) + \
            (f" (+{len(v) - 6} more)" if len(v) > 6 else "")
    return str(v)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class AuditEngine:
    def __init__(self, baseline_path: str = DEFAULT_BASELINE):
        with open(baseline_path, "r", encoding="utf-8") as fh:
            self.baseline = json.load(fh)
        self.controls = self.baseline["controls"]
        self.weights = self.baseline.get(
            "severity_weights", {"High": 5, "Medium": 3, "Low": 1})

    # -- single control ----------------------------------------------------
    def _assess(self, ctl: dict, flat: Dict[str, Any],
                attestations: Dict[str, Any],
                scoped_out: set) -> ControlResult:

        cid = ctl["id"]
        results: List[CheckResult] = []

        for c in ctl.get("checks", []):
            observed = flat.get(c["field"])
            expected = c.get("value")
            ok = evaluate_op(c["op"], observed, expected)
            results.append(CheckResult(
                label=c.get("label", c["field"]),
                field=c["field"], op=c["op"],
                expected=expected, observed=observed, passed=ok,
                detail=f"observed: {_fmt(observed)}"))

        attested = attestations.get(ctl.get("attestation")) if ctl.get("attestation") else None

        # ---- status resolution
        if cid in scoped_out:
            status = NA
        else:
            usable = [r for r in results if r.passed is not None]
            passed = sum(1 for r in usable if r.passed)

            if not results:                                  # pure manual control
                if attested is True:
                    status = PASS
                elif attested is False:
                    status = FAIL
                else:
                    status = MANUAL
            elif not usable:                                 # checks exist, no telemetry
                if attested is True:
                    status = PASS
                elif attested is False:
                    status = FAIL
                else:
                    status = NO_DATA
            else:
                if passed == len(usable):
                    status = PASS
                elif passed == 0:
                    status = FAIL
                else:
                    status = PARTIAL
                # a negative attestation overrides a technically-clean result
                if attested is False and status == PASS:
                    status = PARTIAL
                # hybrid controls need the attestation too before claiming full pass
                if ctl["mode"] == "hybrid" and status == PASS and attested is None:
                    status = PARTIAL

        score = {PASS: 1.0, PARTIAL: 0.5}.get(status, 0.0)
        risk = "None" if status in (PASS, NA) else (
            "Low" if status == MANUAL and ctl["severity"] == "Low" else ctl["severity"])
        if status == PARTIAL and ctl["severity"] == "High":
            risk = "Medium"          # partially mitigated high risk steps down one level

        failing = [r.label for r in results if r.passed is False]
        missing = [r.label for r in results if r.passed is None]
        if status == PASS:
            evidence = "All configured checks satisfied." if results else \
                "Attested as implemented."
        elif status == NA:
            evidence = "Scoped out of this assessment."
        elif status == MANUAL:
            evidence = "Requires auditor attestation — no technical evidence available."
        elif status == NO_DATA:
            evidence = "Telemetry did not include: " + "; ".join(missing[:4])
        else:
            evidence = "Failed: " + "; ".join(failing[:4]) + \
                (f" (+{len(failing) - 4} more)" if len(failing) > 4 else "")
            if missing:
                evidence += f" | Not collected: {len(missing)} check(s)"

        return ControlResult(
            id=cid, title=ctl["title"], theme=ctl["theme"],
            objective=ctl["objective"], mode=ctl["mode"], severity=ctl["severity"],
            status=status, risk=risk, score=score, checks=results,
            remediation=ctl.get("remediation", []), evidence=evidence,
            attestation=ctl.get("attestation"))

    # -- whole assessment --------------------------------------------------
    def run(self, flat: Dict[str, Any],
            attestations: Optional[Dict[str, Any]] = None,
            scoped_out: Optional[set] = None,
            include_manual_as_fail: bool = False) -> "AuditReport":

        attestations = attestations or {}
        # telemetry may carry its own attestations block
        for k, v in flat.items():
            if k.startswith("attestations.") and k.split(".", 1)[1] not in attestations:
                if v is not None:
                    attestations[k.split(".", 1)[1]] = v

        scoped_out = scoped_out or set()
        results = [self._assess(c, flat, attestations, scoped_out) for c in self.controls]
        return AuditReport(results, self.weights, flat, include_manual_as_fail)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

class AuditReport:
    def __init__(self, results: List[ControlResult], weights: dict,
                 flat: Dict[str, Any], include_manual_as_fail: bool = False):
        self.results = results
        self.weights = weights
        self.flat = flat
        self.include_manual_as_fail = include_manual_as_fail
        self.generated = datetime.now(timezone.utc)

    # -- headline figures --------------------------------------------------
    @property
    def counts(self) -> Dict[str, int]:
        c = {k: 0 for k in (PASS, PARTIAL, FAIL, MANUAL, NO_DATA, NA)}
        for r in self.results:
            c[r.status] += 1
        return c

    @property
    def assessed(self) -> List[ControlResult]:
        keep = {PASS, PARTIAL, FAIL}
        if self.include_manual_as_fail:
            keep |= {MANUAL, NO_DATA}
        return [r for r in self.results if r.status in keep]

    @property
    def compliance_score(self) -> float:
        pool = self.assessed
        if not pool:
            return 0.0
        num = sum(self.weights.get(r.severity, 1) * r.score for r in pool)
        den = sum(self.weights.get(r.severity, 1) for r in pool)
        return round(100.0 * num / den, 1) if den else 0.0

    @property
    def raw_score(self) -> float:
        """Unweighted percentage of assessed controls that fully pass."""
        pool = self.assessed
        if not pool:
            return 0.0
        return round(100.0 * sum(1 for r in pool if r.status == PASS) / len(pool), 1)

    @property
    def coverage(self) -> float:
        """Percentage of the 93 Annex A controls that produced a real verdict.

        A high score derived from a handful of controls is not a high score. The
        UI and PDF surface this alongside the headline figure so a thin telemetry
        file cannot be mistaken for a clean audit.
        """
        if not self.results:
            return 0.0
        return round(100.0 * len(self.assessed) / len(self.results), 1)

    @property
    def coverage_warning(self) -> Optional[str]:
        cov = self.coverage
        if cov < 25:
            return (f"Only {cov}% of Annex A controls could be assessed. The compliance "
                    f"score is calculated from a small subset and is not representative. "
                    f"Re-run the collector elevated, or record attestations.")
        if cov < 50:
            return (f"{cov}% of Annex A controls assessed. Record attestations for the "
                    f"procedural controls to make the score representative.")
        return None

    @property
    def maturity(self) -> str:
        if self.coverage < 25:
            return "Insufficient coverage — score not representative"
        s = self.compliance_score
        if s >= 90:
            return "Optimised — certification ready"
        if s >= 75:
            return "Managed — minor gaps"
        if s >= 55:
            return "Defined — material gaps"
        if s >= 35:
            return "Developing — significant remediation required"
        return "Initial — critical exposure"

    @property
    def risk_counts(self) -> Dict[str, int]:
        c = {"High": 0, "Medium": 0, "Low": 0}
        for r in self.results:
            if r.status in (FAIL, PARTIAL, NO_DATA) and r.risk in c:
                c[r.risk] += 1
        return c

    def theme_breakdown(self) -> List[dict]:
        themes: Dict[str, dict] = {}
        for r in self.results:
            t = themes.setdefault(r.theme, {
                "Theme": r.theme, "Total": 0, PASS: 0, PARTIAL: 0,
                FAIL: 0, MANUAL: 0, NO_DATA: 0, NA: 0,
                "_num": 0.0, "_den": 0.0})
            t["Total"] += 1
            t[r.status] += 1
            if r.status in (PASS, PARTIAL, FAIL) or (
                    self.include_manual_as_fail and r.status in (MANUAL, NO_DATA)):
                w = self.weights.get(r.severity, 1)
                t["_num"] += w * r.score
                t["_den"] += w
        out = []
        for t in themes.values():
            t["Compliance %"] = round(100 * t["_num"] / t["_den"], 1) if t["_den"] else 0.0
            t.pop("_num"), t.pop("_den")
            out.append(t)
        return sorted(out, key=lambda x: x["Theme"])

    # -- tabular views -----------------------------------------------------
    def rows(self) -> List[dict]:
        return [r.to_row() for r in self.results]

    def failed(self) -> List[ControlResult]:
        return [r for r in self.results if r.status in (FAIL, PARTIAL)]

    def roadmap(self) -> List[dict]:
        """Prioritised remediation roadmap: risk desc, then status, then control id."""
        pool = [r for r in self.results if r.status in (FAIL, PARTIAL, NO_DATA, MANUAL)]
        pool.sort(key=lambda r: (RISK_ORDER.get(r.risk, 9),
                                 STATUS_ORDER.index(r.status), r.id))
        roadmap = []
        for i, r in enumerate(pool, start=1):
            if r.risk == "High" and r.status in (FAIL, PARTIAL):
                window = "0-30 days"
                phase = "Phase 1 — Immediate"
            elif r.risk in ("High", "Medium") and r.status in (FAIL, PARTIAL, NO_DATA):
                window = "30-90 days"
                phase = "Phase 2 — Short term"
            else:
                window = "90-180 days"
                phase = "Phase 3 — Planned"
            roadmap.append({
                "Priority": i,
                "Phase": phase,
                "Target Window": window,
                "Control": r.id,
                "Title": r.title,
                "Theme": r.theme,
                "Status": r.status,
                "Risk": r.risk,
                "Finding": r.evidence,
                "Failed Checks": [c.label for c in r.checks if c.passed is False],
                "Remediation Steps": r.remediation,
            })
        return roadmap

    def to_dict(self) -> dict:
        return {
            "generated_utc": self.generated.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "host": self.flat.get("metadata.hostname", "Unknown"),
            "os": self.flat.get("metadata.os_caption", "Unknown"),
            "compliance_score": self.compliance_score,
            "raw_score": self.raw_score,
            "coverage": self.coverage,
            "coverage_warning": self.coverage_warning,
            "maturity": self.maturity,
            "counts": self.counts,
            "risk_counts": self.risk_counts,
            "themes": self.theme_breakdown(),
            "controls": [asdict(r) for r in self.results],
            "roadmap": self.roadmap(),
        }
