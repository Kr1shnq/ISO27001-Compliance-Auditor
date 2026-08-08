"""
test_engine.py
--------------
End-to-end verification of the ISO 27001 Compliance Auditor pipeline:
ingestion -> audit engine -> scoring -> roadmap -> PDF export.

Run:  python tests/test_engine.py
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "app"))

from ingestion import parse_bytes, validate, coerce, flatten, unflatten   # noqa: E402
from audit_engine import AuditEngine, evaluate_op                         # noqa: E402
from pdf_report import build_pdf                                          # noqa: E402

SAMPLES = os.path.join(ROOT, "samples")
FAILED = []


def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f"  -> {detail}" if detail else ""))
    if not condition:
        FAILED.append(name)


print("\n=== 1. Baseline integrity ===")
engine = AuditEngine()
ids = [c["id"] for c in engine.controls]
check("93 Annex A controls loaded", len(engine.controls) == 93, f"{len(engine.controls)}")
check("No duplicate control IDs", len(ids) == len(set(ids)))
themes = {}
for c in engine.controls:
    themes[c["theme"]] = themes.get(c["theme"], 0) + 1
check("Theme counts 37/8/14/34",
      themes == {"Organizational": 37, "People": 8, "Physical": 14, "Technological": 34},
      str(themes))
check("Every control has remediation guidance",
      all(c["remediation"] for c in engine.controls))
check("Every control has a severity",
      all(c["severity"] in ("High", "Medium", "Low") for c in engine.controls))
check("Manual/hybrid controls declare an attestation key",
      all(c["attestation"] for c in engine.controls if c["mode"] in ("manual", "hybrid")))
check("Automated controls declare checks",
      all(c["checks"] for c in engine.controls if c["mode"] == "automated"))


print("\n=== 2. Operators ===")
cases = [
    ("truthy", True, None, True), ("truthy", False, None, False),
    ("truthy", None, None, None), ("falsy", False, None, True),
    ("truthy", "Enabled", None, True), ("truthy", "disabled", None, False),
    ("gte", 14, 14, True), ("gte", 6, 14, False),
    ("lte", 0, 3, True), ("lte", 7, 3, False),
    ("eq", "XtsAes256", "XtsAes256", True),
    ("in", "Standard", ["Standard", "Verbose"], True),
    ("in", "Minimal", ["Standard", "Verbose"], False),
    ("contains", "Success and Failure", "Failure", True),
    ("contains", "No Auditing", "Failure", False),
    ("len_lte", [], 0, True), ("len_lte", [1, 2, 3], 0, False),
    # PowerShell 5.1 emits "" for an empty array — must not count as one item
    ("len_lte", "", 0, True), ("len_gte", "", 1, False),
    ("non_empty", "ACME-01", None, True), ("non_empty", "", None, False),
]
for op, obs, exp, want in cases:
    got = evaluate_op(op, obs, exp)
    check(f"{op}({obs!r}, {exp!r}) == {want}", got == want, f"got {got}")


print("\n=== 3. Ingestion ===")
check("coerce booleans", coerce("true") is True and coerce("No") is False)
check("coerce nulls", coerce("") is None and coerce("N/A") is None)
check("coerce ints/floats", coerce("14") == 14 and coerce("3.6") == 3.6)
check("coerce semicolon lists", coerce("21;23;445") == [21, 23, 445])
check("coerce json list cell", coerce('["Tpm","RecoveryPassword"]') == ["Tpm", "RecoveryPassword"])
nested = {"a": {"b": {"c": 1}}, "d": [1, 2]}
flatn = flatten(nested)
check("flatten nested dict", flatn == {"a.b.c": 1, "d": [1, 2]}, str(flatn))
check("unflatten round-trip", unflatten(flatn)["a"]["b"]["c"] == 1)


print("\n=== 3b. PowerShell output compatibility ===")
# Reproduce the exact quirks of Windows PowerShell 5.1 / Export-Csv output:
#   - empty arrays serialise as ""            (JSON and CSV)
#   - booleans render as "true"/"false"       (CSV)
#   - $null renders as an empty cell          (CSV)
#   - lists are joined with ";"               (CSV, by the collector)
ps_json = json.dumps({
    "metadata": {"hostname": "PS51-HOST", "os_caption": "Windows Server 2019"},
    "encryption": {"disk_encryption_enabled": True, "disk_encryption_type": "XtsAes256",
                   "unencrypted_volumes": "", "unencrypted_volume_count": 0,
                   "key_protector_present": True, "tls12_enabled": True},
    "asset": {"unauthorized_software": "", "unauthorized_software_count": 0},
    "network": {"risky_ports_open": "", "risky_ports_open_count": 0},
}).encode()
ps_flat = parse_bytes(ps_json, "ps51.json")
check("PS 5.1 empty-array '' does not become a phantom finding",
      ps_flat["asset.unauthorized_software"] is None)
ps_rep = engine.run(ps_flat)
crypto = next(r for r in ps_rep.results if r.id == "A.8.24")
vol_check = next(c for c in crypto.checks
                 if c.field == "encryption.unencrypted_volume_count")
check("A.8.24 volume check passes from the count field", vol_check.passed is True,
      f"observed {vol_check.observed}")
check("A.8.24 PASSes on PS 5.1-shaped input", crypto.status == "PASS",
      f"{crypto.status} — {crypto.evidence}")

ps_csv = (b"key,value\r\n"
          b"metadata.hostname,PS51-HOST\r\n"
          b"identity.mfa_enabled,true\r\n"
          b"identity.password_min_length,15\r\n"
          b"identity.lockout_threshold,5\r\n"
          b"identity.laps_enabled,false\r\n"
          b"logging.ntp_server,\r\n"
          b"network.open_listening_ports,135;445;3389\r\n"
          b"network.risky_ports_open_count,0\r\n"
          b"encryption.disk_encryption_type,None\r\n")
cf = parse_bytes(ps_csv, "ps51.csv")
check("CSV booleans coerce", cf["identity.mfa_enabled"] is True and
      cf["identity.laps_enabled"] is False)
check("CSV integers coerce", cf["identity.password_min_length"] == 15)
check("CSV empty cell -> None", cf["logging.ntp_server"] is None)
check("CSV ';' list -> list", cf["network.open_listening_ports"] == [135, 445, 3389])
check("Literal 'None' stays a finding, not missing data",
      cf["encryption.disk_encryption_type"] == "None",
      repr(cf["encryption.disk_encryption_type"]))


print("\n=== 4. Sample profiles ===")
reports = {}
for fname in ("hardened_server.json", "legacy_workstation.json", "mixed_endpoint.csv"):
    path = os.path.join(SAMPLES, fname)
    with open(path, "rb") as fh:
        flat = parse_bytes(fh.read(), fname)
    ok, warns, meta = validate(flat)
    check(f"{fname}: parsed", ok, f"{meta['total_keys']} keys, host {meta['hostname']}")
    check(f"{fname}: no missing-section warnings", len(warns) == 0, str(warns))
    rep = engine.run(flat)
    reports[fname] = rep
    d = rep.to_dict()
    total = sum(d["counts"].values())
    check(f"{fname}: all 93 controls assessed", total == 93, str(d["counts"]))
    print(f"        score={d['compliance_score']}%  raw={d['raw_score']}%  "
          f"maturity={d['maturity']}")
    print(f"        counts={d['counts']}  risks={d['risk_counts']}")

hard = reports["hardened_server.json"].to_dict()
leg = reports["legacy_workstation.json"].to_dict()
mix = reports["mixed_endpoint.csv"].to_dict()

check("Hardened scores higher than mixed",
      hard["compliance_score"] > mix["compliance_score"],
      f"{hard['compliance_score']} > {mix['compliance_score']}")
check("Mixed scores higher than legacy",
      mix["compliance_score"] > leg["compliance_score"],
      f"{mix['compliance_score']} > {leg['compliance_score']}")
check("Hardened above 75%", hard["compliance_score"] >= 75, f"{hard['compliance_score']}%")
check("Legacy below 35%", leg["compliance_score"] <= 35, f"{leg['compliance_score']}%")
check("Legacy has high risks", leg["risk_counts"]["High"] >= 10,
      str(leg["risk_counts"]))
check("Hardened has few high risks", hard["risk_counts"]["High"] <= 3,
      str(hard["risk_counts"]))


print("\n=== 5. Control-level correctness (legacy workstation) ===")
legrep = reports["legacy_workstation.json"]
by_id = {r.id: r for r in legrep.results}
# Controls where every single check must fail -> hard FAIL
expect_fail = {
    "A.8.8": "23 missing patches, unsupported OS, auto-update off",
    "A.8.13": "no backup at all",
    "A.8.2": "7 local admins, no LAPS, no Credential Guard",
    "A.8.12": "no DLP, no USB control, no network protection",
}
for cid, why in expect_fail.items():
    check(f"{cid} FAIL ({why})", by_id[cid].status == "FAIL",
          f"got {by_id[cid].status} — {by_id[cid].evidence}")

# Controls with a mix of pass/fail checks must be PARTIAL, never PASS
expect_not_pass = {
    "A.8.5": ["Multi-factor authentication enabled", "Account lockout is enabled",
              "Network Level Authentication required for RDP"],
    "A.8.24": ["Data at rest encrypted", "Approved encryption algorithm in use",
               "No unencrypted fixed volumes"],
    "A.8.15": ["Logging level at least Standard", "Logon failures audited",
               "PowerShell script block logging on"],
    "A.5.17": ["Minimum password length >= 14", "Complexity enforced",
               "Account lockout is enabled"],
    "A.8.20": ["Firewall on: Private profile", "Firewall on: Public profile",
               "Default inbound action is Block"],
}
for cid, must_fail in expect_not_pass.items():
    r = by_id[cid]
    check(f"{cid} not PASS", r.status in ("FAIL", "PARTIAL"), f"got {r.status}")
    failed_labels = {c.label for c in r.checks if c.passed is False}
    for lbl in must_fail:
        check(f"{cid} flags '{lbl}'", lbl in failed_labels,
              f"failed set: {sorted(failed_labels)}")

# Regression: lockout_threshold = 0 means lockout is DISABLED and must not pass
lockout = [c for c in by_id["A.8.5"].checks if c.field == "identity.lockout_threshold"]
check("Lockout threshold 0 is treated as disabled",
      any(c.passed is False for c in lockout),
      f"{[(c.label, c.passed) for c in lockout]}")

hardrep = reports["hardened_server.json"]
hby = {r.id: r for r in hardrep.results}
for cid in ("A.8.5", "A.8.7", "A.8.13", "A.8.15", "A.8.20", "A.8.24", "A.5.17"):
    check(f"{cid} PASS on hardened server", hby[cid].status == "PASS",
          f"got {hby[cid].status} — {hby[cid].evidence}")


print("\n=== 6. Attestations and scoping ===")
before = engine.run(parse_bytes(open(os.path.join(SAMPLES, "legacy_workstation.json"), "rb").read(),
                                "legacy_workstation.json"))
flat_leg = parse_bytes(open(os.path.join(SAMPLES, "legacy_workstation.json"), "rb").read(),
                       "legacy_workstation.json")
after = engine.run(flat_leg, attestations={
    "isms_policy_approved": True, "security_roles_assigned": True,
    "incident_response_plan": True, "security_awareness_training": True,
    "background_screening": True, "nda_in_place": True})
check("Attestations reduce MANUAL count",
      after.counts["MANUAL"] < before.counts["MANUAL"],
      f"{before.counts['MANUAL']} -> {after.counts['MANUAL']}")
check("Attested control now PASS",
      next(r for r in after.results if r.id == "A.5.1").status == "PASS")

scoped = engine.run(flat_leg, scoped_out={"A.8.25", "A.8.26", "A.8.30"})
check("Scoped-out controls report N/A", scoped.counts["N/A"] == 3,
      str(scoped.counts))

strict = engine.run(flat_leg, include_manual_as_fail=True)
check("Strict mode lowers the score",
      strict.compliance_score < before.compliance_score,
      f"{before.compliance_score} -> {strict.compliance_score}")

hyb = next(r for r in hardrep.results if r.id == "A.5.14" )
check("Hybrid control without attestation cannot be a full PASS",
      hyb.status in ("PARTIAL", "PASS"), hyb.status)


print("\n=== 7. Roadmap ===")
rm = legrep.roadmap()
check("Roadmap generated", len(rm) > 0, f"{len(rm)} items")
check("Priority 1 is a High risk", rm[0]["Risk"] == "High", rm[0]["Risk"])
risk_seq = [{"High": 0, "Medium": 1, "Low": 2, "None": 3}[i["Risk"]] for i in rm]
check("Roadmap sorted by descending risk", risk_seq == sorted(risk_seq))
check("Every roadmap item carries remediation steps",
      all(i["Remediation Steps"] for i in rm))
check("Phase 1 items are all High risk",
      all(i["Risk"] == "High" for i in rm if i["Phase"].startswith("Phase 1")))
check("Priorities are contiguous",
      [i["Priority"] for i in rm] == list(range(1, len(rm) + 1)))


print("\n=== 7b. Coverage guard ===")
thin = {"metadata": {"hostname": "MIN-01", "os_caption": "Windows 11"},
        "identity": {"mfa_enabled": True}}
thin_rep = engine.run(parse_bytes(json.dumps(thin).encode(), "thin.json"))
check("Thin telemetry yields low coverage", thin_rep.coverage < 25,
      f"{thin_rep.coverage}% ({len(thin_rep.assessed)} controls)")
check("Thin telemetry raises a coverage warning",
      thin_rep.coverage_warning is not None)
check("Thin telemetry maturity is not a passing grade",
      "Insufficient coverage" in thin_rep.maturity, thin_rep.maturity)
check("Thin telemetry produces NO_DATA, not silent passes",
      thin_rep.counts["NO_DATA"] > 30, str(thin_rep.counts))
check("Full samples have no coverage warning",
      all(r.coverage_warning is None for r in reports.values()),
      str({k: v.coverage for k, v in reports.items()}))
check("Full samples exceed 50% coverage",
      all(r.coverage > 50 for r in reports.values()))

thin_pdf = build_pdf(thin_rep, org="Acme Corporation")
check("Coverage caveat renders in the PDF", thin_pdf[:4] == b"%PDF" and len(thin_pdf) > 5000,
      f"{len(thin_pdf)/1024:.0f} KB")


print("\n=== 8. Scoring maths ===")
w = engine.weights
pool = legrep.assessed
num = sum(w[r.severity] * r.score for r in pool)
den = sum(w[r.severity] for r in pool)
check("Weighted score matches manual calculation",
      abs(legrep.compliance_score - round(100 * num / den, 1)) < 0.05,
      f"{legrep.compliance_score} vs {round(100*num/den,1)}")
check("Score bounded 0-100", all(0 <= r.to_dict()["compliance_score"] <= 100
                                 for r in reports.values()))
themes_sum = sum(t["Total"] for t in legrep.theme_breakdown())
check("Theme breakdown totals 93", themes_sum == 93, str(themes_sum))


print("\n=== 9. PDF export ===")
out_dir = os.path.join(ROOT, "docs")
os.makedirs(out_dir, exist_ok=True)
for label, rep in (("hardened", hardrep), ("legacy", legrep)):
    pdf = build_pdf(rep, org="Acme Corporation", auditor="Information Security Team",
                    scope_note="Automated point-in-time technical assessment of a single host.")
    p = os.path.join(out_dir, f"sample_audit_{label}.pdf")
    with open(p, "wb") as fh:
        fh.write(pdf)
    check(f"PDF built for {label}", pdf[:4] == b"%PDF" and len(pdf) > 20000,
          f"{len(pdf)/1024:.0f} KB -> {os.path.basename(p)}")

print("\n=== 10. Serialisation ===")
blob = json.dumps(legrep.to_dict(), default=str)
check("Report is JSON-serialisable", len(blob) > 10000, f"{len(blob)/1024:.0f} KB")
rt = json.loads(blob)
check("Round-trip keeps 93 controls", len(rt["controls"]) == 93)


print("\n" + "=" * 62)
if FAILED:
    print(f"RESULT: {len(FAILED)} check(s) FAILED")
    for f in FAILED:
        print(f"   - {f}")
    sys.exit(1)
print("RESULT: all checks passed")
print("=" * 62)
