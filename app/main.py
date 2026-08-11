"""
ISO 27001 Compliance Auditor
============================
Streamlit web application that automates gap analysis of system configuration
telemetry against all 93 ISO/IEC 27001:2022 Annex A controls.

Run:
    streamlit run app/main.py
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ingestion import parse_bytes, validate, unflatten          # noqa: E402
from audit_engine import AuditEngine, DEFAULT_BASELINE          # noqa: E402
from pdf_report import build_pdf                                # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_DIR = os.path.join(ROOT, "samples")
COLLECTOR = os.path.join(ROOT, "collector", "Collect-ISOTelemetry.ps1")

PALETTE = {
    "PASS": "#16a34a", "PARTIAL": "#ca8a04", "FAIL": "#dc2626",
    "MANUAL": "#2563eb", "NO_DATA": "#94a3b8", "N/A": "#cbd5e1",
}
RISK_PALETTE = {"High": "#dc2626", "Medium": "#ca8a04", "Low": "#16a34a", "None": "#94a3b8"}

st.set_page_config(page_title="ISO 27001 Compliance Auditor",
                   page_icon="[]", layout="wide",
                   initial_sidebar_state="expanded")

st.markdown("""
<style>
  .block-container {padding-top: 2rem; max-width: 1400px;}
  [data-testid="stMetricValue"] {font-size: 1.9rem;}
  .hero {background: linear-gradient(100deg,#112240 0%,#1e3a5f 100%);
         padding: 1.4rem 1.6rem; border-radius: 12px; color: #fff; margin-bottom: 1.2rem;}
  .hero h1 {margin:0; font-size:1.55rem; font-weight:700; color:#fff;}
  .hero p  {margin:.35rem 0 0; opacity:.85; font-size:.9rem;}
  .pill {display:inline-block;padding:2px 10px;border-radius:999px;
         font-size:.72rem;font-weight:700;color:#fff;}
  .findcard {border:1px solid #e2e8f0;border-left:5px solid #dc2626;border-radius:8px;
             padding:.8rem 1rem;margin-bottom:.7rem;background:#fff;}
  .findcard h4 {margin:0 0 .25rem;font-size:.95rem;color:#112240;}
  .muted {color:#64748b;font-size:.82rem;}
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Cached resources
# ---------------------------------------------------------------------------

@st.cache_resource(show_spinner=False)
def get_engine(path: str):
    return AuditEngine(path)


@st.cache_data(show_spinner=False)
def load_sample(name: str) -> bytes:
    with open(os.path.join(SAMPLE_DIR, name), "rb") as fh:
        return fh.read()


@st.cache_data(show_spinner=False)
def load_collector() -> bytes | None:
    """Read the PowerShell collector so it can be offered as a download.

    Returns None rather than raising if the script is absent, so a partial
    deployment degrades to an instruction instead of a broken landing page.
    """
    try:
        with open(COLLECTOR, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def ss(key, default):
    if key not in st.session_state:
        st.session_state[key] = default
    return st.session_state[key]


ss("flat", None)
ss("source_name", None)
ss("attestations", {})
ss("scoped_out", set())


# ---------------------------------------------------------------------------
# Sidebar — ingestion & options
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("### Audit configuration")

    org = st.text_input("Organisation", "Acme Corporation")
    auditor = st.text_input("Prepared by", "Information Security Team")

    st.divider()
    st.markdown("#### 1. Ingest telemetry")
    up = st.file_uploader("System configuration report", type=["json", "csv", "tsv", "txt"],
                          help="Output of Collect-ISOTelemetry.ps1, or any JSON/CSV "
                               "using the documented key schema.")

    samples = sorted(f for f in os.listdir(SAMPLE_DIR)) if os.path.isdir(SAMPLE_DIR) else []
    sample_pick = st.selectbox("…or load a bundled sample", ["—"] + samples)

    col_a, col_b = st.columns(2)
    do_load = col_a.button("Load", width="stretch", type="primary")
    if col_b.button("Reset", width="stretch"):
        st.session_state.flat = None
        st.session_state.attestations = {}
        st.session_state.scoped_out = set()
        st.rerun()

    if do_load:
        try:
            if up is not None:
                st.session_state.flat = parse_bytes(up.getvalue(), up.name)
                st.session_state.source_name = up.name
            elif sample_pick != "—":
                st.session_state.flat = parse_bytes(load_sample(sample_pick), sample_pick)
                st.session_state.source_name = sample_pick
            else:
                st.warning("Choose a file or a sample first.")
        except Exception as exc:                                  # noqa: BLE001
            st.error(f"Could not parse the file: {exc}")

    st.divider()
    st.markdown("#### 2. Scoring options")
    strict = st.toggle("Strict mode", value=False,
                       help="Count unattested manual controls and missing telemetry as "
                            "failures — the conservative posture a certification auditor "
                            "would take.")
    baseline_path = st.text_input("Baseline file", DEFAULT_BASELINE)

    st.divider()
    st.caption("ISO 27001 Compliance Auditor v1.0 · "
               "ISO/IEC 27001:2022 Annex A · 93 controls")


engine = get_engine(baseline_path)

st.markdown(
    '<div class="hero"><h1>ISO 27001 Compliance Auditor</h1>'
    '<p>Automated Annex A gap analysis · real-time compliance visibility · '
    'actionable remediation roadmap</p></div>', unsafe_allow_html=True)

if st.session_state.flat is None:
    left, right = st.columns([1.35, 1])
    with left:
        st.subheader("Get started")
        st.markdown("""
1. **Collect telemetry** — click below to download the telemetry-fetching PowerShell
   script, then run it as Administrator on the target Windows host to generate a
   configuration report.
        """)

        collector = load_collector()
        if collector is not None:
            st.download_button(
                "Download Collect-ISOTelemetry.ps1",
                data=collector,
                file_name="Collect-ISOTelemetry.ps1",
                mime="application/octet-stream",
                type="primary",
                help="Read-only inventory of the local Windows host. Changes no "
                     "setting, installs nothing and makes no outbound connection.")
        else:
            st.warning("The collector script is not bundled with this deployment — "
                       "fetch it from `collector/Collect-ISOTelemetry.ps1` in the "
                       "repository.")

        # Numbering continues from 1 above: CommonMark takes an ordered list's start
        # value from its first item, so this block renders as 2-5 rather than 1-4.
        st.markdown("""
2. **Upload** the report in the sidebar (or load a bundled sample to explore).
3. **Review** the dashboard, control register and remediation roadmap.
4. **Attest** the organisational controls that cannot be measured technically.
5. **Export** a management-ready PDF audit summary.
        """)
        st.info("The engine evaluates all 93 Annex A:2022 controls — 20 fully automated, "
                "27 hybrid (telemetry + attestation) and 46 procedural.")
    with right:
        st.subheader("Expected schema")
        st.code("""{
  "metadata":   { "hostname", "os_caption", "collected_utc" },
  "identity":   { "mfa_enabled", "password_min_length", ... },
  "encryption": { "disk_encryption_type", "tls12_enabled", ... },
  "logging":    { "logging_level", "audit_logon_events", ... },
  "endpoint_protection": { "antivirus_enabled", "firewall_domain", ... },
  "patching":   { "missing_critical_patches", "os_supported", ... },
  "network":    { "rdp_nla_required", "risky_ports_open", ... },
  "backup":     { "backup_configured", "backup_encrypted", ... },
  "attestations": { "isms_policy_approved": true, ... }
}""", language="json")
    st.stop()


# ---------------------------------------------------------------------------
# Run the audit
# ---------------------------------------------------------------------------

flat = st.session_state.flat
ok, warnings, meta = validate(flat)
report = engine.run(flat,
                    attestations=dict(st.session_state.attestations),
                    scoped_out=set(st.session_state.scoped_out),
                    include_manual_as_fail=strict)
d = report.to_dict()
df = pd.DataFrame(report.rows())

st.caption(
    f"**{meta['hostname']}** · {meta['os']} · collected {meta['collected_utc']} · "
    f"source `{st.session_state.source_name}` · "
    f"{meta['populated_keys']}/{meta['total_keys']} parameters populated")

if d["coverage_warning"]:
    st.warning(f"**Assessment coverage {d['coverage']}%** — {d['coverage_warning']}")

if warnings:
    with st.expander(f"Ingestion warnings ({len(warnings)})"):
        for w in warnings:
            st.warning(w)

# ---- headline metrics
score = d["compliance_score"]
c = d["counts"]
m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("Weighted compliance", f"{score}%", d["maturity"].split("—")[0].strip())
m2.metric("Passed", c["PASS"])
m3.metric("Failed", c["FAIL"], delta=f"-{c['FAIL']}" if c["FAIL"] else None,
          delta_color="inverse")
m4.metric("Partial", c["PARTIAL"])
m5.metric("Manual / no data", c["MANUAL"] + c["NO_DATA"])
m6.metric("High risks open", d["risk_counts"]["High"],
          delta=f"-{d['risk_counts']['High']}" if d["risk_counts"]["High"] else None,
          delta_color="inverse")

tabs = st.tabs(["Dashboard", "Control register", "Remediation roadmap",
                "Manual attestations", "Evidence", "Export"])


# ---------------------------------------------------------------------------
# Tab 1 — Dashboard
# ---------------------------------------------------------------------------
with tabs[0]:
    g1, g2 = st.columns([1, 1.5])

    with g1:
        gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": "%", "font": {"size": 46}},
            title={"text": "Weighted Annex A compliance", "font": {"size": 14}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1},
                "bar": {"color": "#112240", "thickness": 0.28},
                "steps": [
                    {"range": [0, 35], "color": "#fecaca"},
                    {"range": [35, 55], "color": "#fed7aa"},
                    {"range": [55, 75], "color": "#fef08a"},
                    {"range": [75, 90], "color": "#bbf7d0"},
                    {"range": [90, 100], "color": "#86efac"}],
                "threshold": {"line": {"color": "#dc2626", "width": 3},
                              "thickness": 0.8, "value": 75}}))
        gauge.update_layout(height=290, margin=dict(t=50, b=10, l=20, r=20))
        st.plotly_chart(gauge, width="stretch")
        st.caption(f"Maturity: **{d['maturity']}** · unweighted pass rate {d['raw_score']}% · "
                   f"assessment coverage {d['coverage']}% "
                   f"({len(report.assessed)} of 93 controls)")

    with g2:
        status_df = pd.DataFrame(
            [{"Status": k, "Controls": v} for k, v in c.items() if v > 0])
        donut = px.pie(status_df, names="Status", values="Controls", hole=0.55,
                       color="Status", color_discrete_map=PALETTE,
                       title="Control status distribution (93 Annex A controls)")
        donut.update_traces(textposition="outside", textinfo="label+value")
        donut.update_layout(height=290, margin=dict(t=50, b=10, l=10, r=10),
                            showlegend=True)
        st.plotly_chart(donut, width="stretch")

    st.markdown("#### Compliance by Annex A theme")
    t1, t2 = st.columns([1.6, 1])

    themes = pd.DataFrame(d["themes"])
    stacked = themes.melt(id_vars=["Theme"],
                          value_vars=["PASS", "PARTIAL", "FAIL", "MANUAL", "NO_DATA", "N/A"],
                          var_name="Status", value_name="Controls")
    stacked = stacked[stacked["Controls"] > 0]
    bar = px.bar(stacked, x="Controls", y="Theme", color="Status", orientation="h",
                 color_discrete_map=PALETTE, text="Controls",
                 category_orders={"Status": ["PASS", "PARTIAL", "FAIL",
                                             "MANUAL", "NO_DATA", "N/A"]})
    bar.update_layout(height=320, margin=dict(t=30, b=10, l=10, r=10),
                      barmode="stack", legend_title="")
    t1.plotly_chart(bar, width="stretch")

    radar = go.Figure()
    radar.add_trace(go.Scatterpolar(
        r=list(themes["Compliance %"]) + [themes["Compliance %"].iloc[0]],
        theta=list(themes["Theme"]) + [themes["Theme"].iloc[0]],
        fill="toself", name="Achieved", line_color="#2563af"))
    radar.add_trace(go.Scatterpolar(
        r=[75] * (len(themes) + 1),
        theta=list(themes["Theme"]) + [themes["Theme"].iloc[0]],
        name="Target (75%)", line=dict(color="#dc2626", dash="dash"), fill=None))
    radar.update_layout(height=320, margin=dict(t=40, b=20, l=40, r=40),
                        polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
                        title="Theme compliance vs target")
    t2.plotly_chart(radar, width="stretch")

    r1, r2 = st.columns([1, 1.6])
    with r1:
        rc = d["risk_counts"]
        risk_df = pd.DataFrame([{"Risk": k, "Findings": v} for k, v in rc.items()])
        rbar = px.bar(risk_df, x="Risk", y="Findings", color="Risk", text="Findings",
                      color_discrete_map=RISK_PALETTE,
                      category_orders={"Risk": ["High", "Medium", "Low"]},
                      title="Open findings by risk level")
        rbar.update_layout(height=300, showlegend=False, margin=dict(t=50, b=10))
        st.plotly_chart(rbar, width="stretch")

    with r2:
        st.markdown("##### Top priority findings")
        top = [x for x in d["roadmap"] if x["Status"] in ("FAIL", "PARTIAL")][:6]
        if not top:
            st.success("No failed or partially implemented controls. "
                       "Remaining gaps are attestation-only.")
        for item in top:
            col = RISK_PALETTE.get(item["Risk"], "#94a3b8")
            st.markdown(
                f'<div class="findcard" style="border-left-color:{col}">'
                f'<h4>{item["Control"]} — {item["Title"]} '
                f'<span class="pill" style="background:{col}">{item["Risk"]}</span></h4>'
                f'<div class="muted">{item["Finding"]}</div>'
                f'<div class="muted"><b>{item["Target Window"]}</b> · '
                f'{item["Phase"]}</div></div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Tab 2 — Control register
# ---------------------------------------------------------------------------
with tabs[1]:
    f1, f2, f3, f4 = st.columns([1.2, 1.2, 1.2, 2.2])
    theme_f = f1.multiselect("Theme", sorted(df["Theme"].unique()))
    status_f = f2.multiselect("Status", [s for s in PALETTE if s in set(df["Status"])])
    risk_f = f3.multiselect("Risk", ["High", "Medium", "Low", "None"])
    query = f4.text_input("Search control ID or title", "")

    view = df.copy()
    if theme_f:
        view = view[view["Theme"].isin(theme_f)]
    if status_f:
        view = view[view["Status"].isin(status_f)]
    if risk_f:
        view = view[view["Risk"].isin(risk_f)]
    if query:
        q = query.lower()
        view = view[view["Control"].str.lower().str.contains(q) |
                    view["Title"].str.lower().str.contains(q)]

    st.caption(f"Showing {len(view)} of {len(df)} controls")
    st.dataframe(
        view, width="stretch", hide_index=True, height=430,
        column_config={
            "Score": st.column_config.ProgressColumn(
                "Score", min_value=0, max_value=1, format="%.1f"),
            "Evidence": st.column_config.TextColumn("Evidence / finding", width="large"),
        })

    st.markdown("#### Control detail")
    pick = st.selectbox("Select a control",
                        [f"{r.id} — {r.title}" for r in report.results])
    cid = pick.split(" — ")[0]
    ctl = next(r for r in report.results if r.id == cid)

    dc1, dc2 = st.columns([1, 1.6])
    with dc1:
        st.markdown(f"**Theme** · {ctl.theme}")
        st.markdown(f"**Assessment mode** · {ctl.mode.capitalize()}")
        st.markdown(f"**Inherent severity** · {ctl.severity}")
        colr = RISK_PALETTE.get(ctl.risk, "#94a3b8")
        cols = PALETTE.get(ctl.status, "#94a3b8")
        st.markdown(
            f'<span class="pill" style="background:{cols}">{ctl.status}</span> '
            f'<span class="pill" style="background:{colr}">Risk: {ctl.risk}</span>',
            unsafe_allow_html=True)
        st.markdown(f"\n**Objective**\n\n{ctl.objective}")
        st.markdown(f"**Finding**\n\n{ctl.evidence}")
    with dc2:
        if ctl.checks:
            st.markdown("**Technical checks**")
            st.dataframe(pd.DataFrame([{
                "Check": ch.label,
                "Result": "PASS" if ch.passed else ("NO DATA" if ch.passed is None else "FAIL"),
                "Telemetry field": ch.field,
                "Rule": f"{ch.op} {ch.expected if ch.expected is not None else ''}".strip(),
                "Observed": "not collected" if ch.observed is None else str(ch.observed),
            } for ch in ctl.checks]), width="stretch", hide_index=True)
        else:
            st.info("This control has no automatable technical check. "
                    "Record an attestation in the Manual attestations tab.")
        if ctl.remediation:
            st.markdown("**Remediation guidance**")
            for i, step in enumerate(ctl.remediation, 1):
                st.markdown(f"{i}. {step}")


# ---------------------------------------------------------------------------
# Tab 3 — Roadmap
# ---------------------------------------------------------------------------
with tabs[2]:
    roadmap = d["roadmap"]
    if not roadmap:
        st.success("Nothing to remediate — every control passed.")
    else:
        rm = pd.DataFrame([{k: v for k, v in r.items()
                            if k not in ("Remediation Steps", "Failed Checks")}
                           for r in roadmap])
        p1, p2 = st.columns([1, 1])
        phase_f = p1.multiselect("Phase", sorted(rm["Phase"].unique()),
                                 default=sorted(rm["Phase"].unique()))
        risk_f2 = p2.multiselect("Risk", ["High", "Medium", "Low"],
                                 default=["High", "Medium", "Low"])
        rmv = rm[rm["Phase"].isin(phase_f) & rm["Risk"].isin(risk_f2)]

        st.markdown("##### Roadmap summary")
        st.dataframe(rmv, width="stretch", hide_index=True, height=300)

        counts = rm.groupby(["Phase", "Risk"]).size().reset_index(name="Items")
        ph = px.bar(counts, x="Phase", y="Items", color="Risk", text="Items",
                    color_discrete_map=RISK_PALETTE,
                    category_orders={"Risk": ["High", "Medium", "Low"]},
                    title="Remediation workload by delivery phase")
        ph.update_layout(height=300, margin=dict(t=50, b=10))
        st.plotly_chart(ph, width="stretch")

        st.markdown("##### Step-by-step technical fixes")
        show = [r for r in roadmap
                if r["Phase"] in phase_f and r["Risk"] in risk_f2][:40]
        for item in show:
            col = RISK_PALETTE.get(item["Risk"], "#94a3b8")
            with st.expander(
                    f"#{item['Priority']}  {item['Control']} — {item['Title']}  "
                    f"·  {item['Risk']} risk  ·  {item['Target Window']}"):
                st.markdown(f"**Status** {item['Status']} &nbsp;|&nbsp; "
                            f"**Theme** {item['Theme']} &nbsp;|&nbsp; "
                            f"**Phase** {item['Phase']}")
                st.markdown(f"**Finding** — {item['Finding']}")
                if item["Failed Checks"]:
                    st.markdown("**Failed checks**")
                    for fc in item["Failed Checks"]:
                        st.markdown(f"- {fc}")
                st.markdown("**Remediation steps**")
                for i, step in enumerate(item["Remediation Steps"], 1):
                    st.markdown(f"{i}. {step}")

        st.download_button(
            "Download roadmap (CSV)",
            rm.to_csv(index=False).encode(),
            file_name=f"iso27001_roadmap_{meta['hostname']}.csv",
            mime="text/csv")


# ---------------------------------------------------------------------------
# Tab 4 — Manual attestations
# ---------------------------------------------------------------------------
with tabs[3]:
    st.markdown("Organisational, people and physical controls cannot be measured from "
                "system telemetry. Record the auditor's determination here — results "
                "update immediately.")

    pending = [r for r in report.results if r.attestation]
    a1, a2 = st.columns([3, 1])
    only_open = a2.toggle("Show unanswered only", value=True)

    with st.form("attest"):
        new = dict(st.session_state.attestations)
        shown = 0
        for theme in ["Organizational", "People", "Physical", "Technological"]:
            group = [r for r in pending if r.theme == theme]
            group = [r for r in group
                     if not only_open or new.get(r.attestation) is None]
            if not group:
                continue
            st.markdown(f"##### {theme}")
            for r in group:
                shown += 1
                cur = new.get(r.attestation)
                idx = {None: 0, True: 1, False: 2}.get(cur, 0)
                choice = st.radio(
                    f"**{r.id}** — {r.title}",
                    ["Not assessed", "Implemented", "Not implemented"],
                    index=idx, horizontal=True, key=f"att_{r.id}",
                    help=r.objective)
                new[r.attestation] = {"Not assessed": None,
                                      "Implemented": True,
                                      "Not implemented": False}[choice]
        if shown == 0:
            st.success("Every attestable control has been answered.")
        if st.form_submit_button("Apply attestations", type="primary"):
            st.session_state.attestations = {k: v for k, v in new.items() if v is not None}
            st.rerun()

    answered = len(st.session_state.attestations)
    a1.progress(answered / max(1, len(pending)),
                text=f"{answered} of {len(pending)} attestable controls answered")

    st.divider()
    ic1, ic2 = st.columns(2)
    ic1.download_button(
        "Export attestations (JSON)",
        json.dumps(st.session_state.attestations, indent=2).encode(),
        file_name="iso27001_attestations.json", mime="application/json")
    imp = ic2.file_uploader("Import attestations (JSON)", type=["json"], key="attimp")
    if imp is not None and ic2.button("Load attestations"):
        st.session_state.attestations = json.loads(imp.getvalue())
        st.rerun()

    st.divider()
    st.markdown("##### Scope exclusions")
    scoped = st.multiselect(
        "Mark controls as Not Applicable (documented justification required for certification)",
        [f"{r.id} — {r.title}" for r in report.results],
        default=[f"{r.id} — {r.title}" for r in report.results
                 if r.id in st.session_state.scoped_out])
    new_scope = {s.split(" — ")[0] for s in scoped}
    if new_scope != set(st.session_state.scoped_out):
        st.session_state.scoped_out = new_scope
        st.rerun()


# ---------------------------------------------------------------------------
# Tab 5 — Evidence
# ---------------------------------------------------------------------------
with tabs[4]:
    st.markdown("#### Ingested configuration parameters")
    ev = pd.DataFrame(
        [{"Parameter": k,
          "Value": ", ".join(str(x) for x in v) if isinstance(v, list)
          else ("(not collected)" if v is None else str(v)),
          "Type": type(v).__name__ if v is not None else "null",
          "Section": k.split(".")[0]}
         for k, v in sorted(flat.items())])
    s1, s2 = st.columns([1, 2])
    sec = s1.multiselect("Section", sorted(ev["Section"].unique()))
    q2 = s2.text_input("Search parameter", "")
    evv = ev
    if sec:
        evv = evv[evv["Section"].isin(sec)]
    if q2:
        evv = evv[evv["Parameter"].str.contains(q2, case=False)]
    st.dataframe(evv, width="stretch", hide_index=True, height=430)

    st.download_button("Download normalised telemetry (JSON)",
                       json.dumps(unflatten(flat), indent=2, default=str).encode(),
                       file_name=f"telemetry_{meta['hostname']}.json",
                       mime="application/json")


# ---------------------------------------------------------------------------
# Tab 6 — Export
# ---------------------------------------------------------------------------
with tabs[5]:
    st.markdown("#### Generate audit deliverables")
    e1, e2 = st.columns([1.2, 1])
    with e1:
        scope_note = st.text_area(
            "Scope and limitations statement (appears on the cover page)",
            "This assessment evaluated a single Windows host using configuration telemetry "
            "collected at a point in time. Organisational, people and physical controls were "
            "assessed by auditor attestation where recorded. The results reflect technical "
            "configuration only and do not replace a full ISMS certification audit.")
        inc_reg = st.checkbox("Include full 93-control register", True)
        inc_road = st.checkbox("Include remediation roadmap and technical fixes", True)
        inc_app = st.checkbox("Include telemetry evidence appendix", True)

        if st.button("Build PDF audit summary", type="primary"):
            with st.spinner("Rendering PDF…"):
                pdf_bytes = build_pdf(report, org=org, auditor=auditor,
                                      scope_note=scope_note,
                                      include_register=inc_reg,
                                      include_roadmap=inc_road,
                                      include_appendix=inc_app)
            st.session_state["pdf_bytes"] = pdf_bytes
            st.success(f"PDF ready — {len(pdf_bytes) / 1024:.0f} KB")

        if st.session_state.get("pdf_bytes"):
            st.download_button(
                "Download PDF audit report",
                st.session_state["pdf_bytes"],
                file_name=f"ISO27001_Audit_{meta['hostname']}_"
                          f"{datetime.now():%Y%m%d}.pdf",
                mime="application/pdf", type="primary")

    with e2:
        st.markdown("##### Other formats")
        st.download_button("Control register (CSV)", df.to_csv(index=False).encode(),
                           file_name=f"iso27001_register_{meta['hostname']}.csv",
                           mime="text/csv", width="stretch")
        st.download_button("Full results (JSON)",
                           json.dumps(d, indent=2, default=str).encode(),
                           file_name=f"iso27001_results_{meta['hostname']}.json",
                           mime="application/json", width="stretch")
        st.markdown("##### Report snapshot")
        st.json({"host": d["host"], "compliance_score": d["compliance_score"],
                 "maturity": d["maturity"], "counts": d["counts"],
                 "risk_counts": d["risk_counts"]}, expanded=False)
