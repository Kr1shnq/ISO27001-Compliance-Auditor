"""
build_guide.py
--------------
Builds `ISO27001_Compliance_Auditor_Guide.pdf` — the overview and user guide for
the ISO 27001 Compliance Auditor web application and its PowerShell collector.

Run:  python docs/build_guide.py
"""

import os
import sys
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, ListFlowable,
                               ListItem, NextPageTemplate, PageBreak, PageTemplate,
                               Paragraph, Spacer, Table, TableStyle)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

OUT = os.path.join(HERE, "ISO27001_Compliance_Auditor_Guide.pdf")

NAVY = colors.HexColor("#112240")
BLUE = colors.HexColor("#2563af")
SLATE = colors.HexColor("#475569")
MUTED = colors.HexColor("#64748b")
LIGHT = colors.HexColor("#f1f5f9")
BORDER = colors.HexColor("#cbd5e1")
GREEN = colors.HexColor("#16a34a")
AMBER = colors.HexColor("#ca8a04")
RED = colors.HexColor("#dc2626")
CODEBG = colors.HexColor("#0f172a")

# ---------------------------------------------------------------------------
# Live figures pulled from the actual baseline and a real audit run
# ---------------------------------------------------------------------------
from core.ingestion import parse_bytes               # noqa: E402
from core.audit_engine import AuditEngine            # noqa: E402

engine = AuditEngine()
MODES = {"automated": 0, "hybrid": 0, "manual": 0}
THEMES = {}
for c in engine.controls:
    MODES[c["mode"]] += 1
    THEMES[c["theme"]] = THEMES.get(c["theme"], 0) + 1

DEMO = {}
for s in ("hardened_server.json", "legacy_workstation.json", "mixed_endpoint.csv"):
    with open(os.path.join(ROOT, "samples", s), "rb") as fh:
        DEMO[s] = engine.run(parse_bytes(fh.read(), s)).to_dict()

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
ss = getSampleStyleSheet()

S = {
    "title": ParagraphStyle("title", parent=ss["Title"], fontName="Helvetica-Bold",
                            fontSize=27, leading=31, textColor=colors.white,
                            alignment=0, spaceAfter=0),
    "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=13,
                               leading=17, textColor=colors.HexColor("#c7d5ea"),
                               alignment=0),
    # keepWithNext stops a heading from stranding at the foot of a page now that
    # sections flow continuously instead of each forcing a page break.
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=16, leading=20,
                         textColor=NAVY, spaceBefore=6, spaceAfter=8,
                         keepWithNext=1),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11.5, leading=15,
                         textColor=BLUE, spaceBefore=10, spaceAfter=4,
                         keepWithNext=1),
    "h3": ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=9.8, leading=13,
                         textColor=NAVY, spaceBefore=7, spaceAfter=2,
                         keepWithNext=1),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9.4, leading=13.8,
                           textColor=SLATE, alignment=TA_JUSTIFY, spaceAfter=5),
    "bullet": ParagraphStyle("bullet", fontName="Helvetica", fontSize=9.2, leading=13,
                             textColor=SLATE),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=8.2, leading=11,
                           textColor=SLATE),
    "cellb": ParagraphStyle("cellb", fontName="Helvetica-Bold", fontSize=8.2,
                            leading=11, textColor=NAVY),
    "cellh": ParagraphStyle("cellh", fontName="Helvetica-Bold", fontSize=8.2,
                            leading=11, textColor=colors.white),
    "code": ParagraphStyle("code", fontName="Courier", fontSize=8.0, leading=11.6,
                           textColor=colors.HexColor("#e2e8f0"),
                           backColor=CODEBG, borderPadding=7,
                           leftIndent=2, rightIndent=2, spaceBefore=3, spaceAfter=7),
    "note": ParagraphStyle("note", fontName="Helvetica", fontSize=8.8, leading=12.4,
                           textColor=NAVY, backColor=LIGHT, borderColor=BORDER,
                           borderWidth=0.6, borderPadding=8, spaceBefore=5,
                           spaceAfter=7, alignment=TA_JUSTIFY),
    "caption": ParagraphStyle("caption", fontName="Helvetica-Oblique", fontSize=8,
                              leading=11, textColor=MUTED, spaceAfter=8),
}


def P(t, s="body"):
    return Paragraph(t, S[s])


def section(heading, *rest):
    """A section heading glued to its opening flowables.

    Sections flow continuously rather than each forcing a new page, so the
    heading must not be able to strand itself at the foot of a page.
    """
    return KeepTogether([P(heading, "h1"), *rest])


def bullets(items, style="bullet"):
    return ListFlowable(
        [ListItem(Paragraph(i, S[style]), leftIndent=12, value="circle")
         for i in items],
        bulletType="bullet", bulletColor=BLUE, bulletFontSize=5,
        leftIndent=12, spaceBefore=2, spaceAfter=6)


def numbered(items):
    return ListFlowable(
        [ListItem(Paragraph(i, S["bullet"]), leftIndent=14) for i in items],
        bulletType="1", bulletColor=BLUE, bulletFontName="Helvetica-Bold",
        bulletFontSize=9, leftIndent=14, spaceBefore=2, spaceAfter=6)


def code(lines):
    body = "<br/>".join(l.replace("&", "&amp;").replace("<", "&lt;").replace(" ", "&nbsp;")
                        for l in lines)
    return Paragraph(body, S["code"])


def table(header, rows, widths, aligns=None, zebra=True):
    data = [[Paragraph(h, S["cellh"]) for h in header]]
    for r in rows:
        data.append([c if hasattr(c, "wrap") else Paragraph(str(c), S["cell"]) for c in r])
    t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, BORDER),
        ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
    ]
    if zebra:
        for i in range(1, len(data)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i), LIGHT))
    for a in (aligns or []):
        style.append(a)
    t.setStyle(TableStyle(style))
    return t


# ---------------------------------------------------------------------------
# Page furniture
# ---------------------------------------------------------------------------

def cover_page(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, A4[1] - 118 * mm, A4[0], 118 * mm, stroke=0, fill=1)
    canvas.setFillColor(BLUE)
    canvas.rect(0, A4[1] - 122 * mm, A4[0], 4 * mm, stroke=0, fill=1)
    # decorative control grid
    canvas.setFillColor(colors.HexColor("#1e3a5f"))
    for row in range(4):
        for col in range(14):
            canvas.rect(20 * mm + col * 12 * mm, A4[1] - 46 * mm - row * 8 * mm,
                        8 * mm, 5 * mm, stroke=0, fill=1)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(20 * mm, 14 * mm,
                      "ISO 27001 Compliance Auditor - Overview and User Guide")
    canvas.drawRightString(A4[0] - 20 * mm, 14 * mm,
                           datetime.now().strftime("%d %B %Y"))
    canvas.restoreState()


def body_page(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(20 * mm, A4[1] - 17 * mm, A4[0] - 20 * mm, A4[1] - 17 * mm)
    canvas.setFont("Helvetica-Bold", 7.6)
    canvas.setFillColor(NAVY)
    canvas.drawString(20 * mm, A4[1] - 15 * mm, "ISO 27001 COMPLIANCE AUDITOR")
    canvas.setFont("Helvetica", 7.6)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(A4[0] - 20 * mm, A4[1] - 15 * mm,
                           "Overview and User Guide")
    canvas.line(20 * mm, 16 * mm, A4[0] - 20 * mm, 16 * mm)
    canvas.setFont("Helvetica", 7.6)
    canvas.drawString(20 * mm, 11 * mm, "ISO/IEC 27001:2022 Annex A - 93 controls")
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(NAVY)
    canvas.drawRightString(A4[0] - 20 * mm, 11 * mm, str(canvas.getPageNumber()))
    canvas.restoreState()


doc = BaseDocTemplate(OUT, pagesize=A4,
                      leftMargin=20 * mm, rightMargin=20 * mm,
                      topMargin=22 * mm, bottomMargin=20 * mm,
                      title="ISO 27001 Compliance Auditor - Overview and User Guide",
                      author="ISO 27001 Compliance Auditor",
                      subject="Application overview, architecture and usage instructions")

cover_frame = Frame(20 * mm, 20 * mm, A4[0] - 40 * mm, A4[1] - 40 * mm, id="cover")
body_frame = Frame(20 * mm, 20 * mm, A4[0] - 40 * mm, A4[1] - 42 * mm, id="body")
doc.addPageTemplates([
    PageTemplate(id="Cover", frames=[cover_frame], onPage=cover_page),
    PageTemplate(id="Body", frames=[body_frame], onPage=body_page),
])

F = []   # flowables

# ===========================================================================
# COVER
# ===========================================================================
F += [
    Spacer(1, 42 * mm),
    P("ISO 27001", "title"),
    P("Compliance Auditor", "title"),
    Spacer(1, 5 * mm),
    P("Automated Annex A gap analysis, real-time compliance<br/>"
      "visibility and actionable remediation roadmaps", "subtitle"),
    Spacer(1, 40 * mm),
]

# NOTE: an inline <font size=..> does not increase a paragraph's leading in
# ReportLab, so a large number and its caption in one Paragraph collide. Each
# stat is therefore two Paragraphs with their own correctly-sized leading.
S["statnum"] = ParagraphStyle("statnum", fontName="Helvetica-Bold", fontSize=21,
                              leading=25, textColor=NAVY, alignment=1,
                              spaceAfter=1)
S["statlbl"] = ParagraphStyle("statlbl", fontName="Helvetica", fontSize=7.2,
                              leading=9.5, textColor=MUTED, alignment=1)


def stat(value, label):
    return [Paragraph(str(value), S["statnum"]), Paragraph(label, S["statlbl"])]


cover_stats = Table([[
    stat(93, "ANNEX A CONTROLS"),
    stat(MODES["automated"] + MODES["hybrid"], "TELEMETRY-DRIVEN"),
    stat(4, "CONTROL THEMES"),
    stat(1, "PDF DELIVERABLE"),
]], colWidths=[42.5 * mm] * 4)
cover_stats.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
    ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
    ("INNERGRID", (0, 0), (-1, -1), 0.6, BORDER),
    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ("TOPPADDING", (0, 0), (-1, -1), 9),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
]))
F += [cover_stats, Spacer(1, 10 * mm)]

F += [table(
    ["", ""],
    [[Paragraph("<b>Document</b>", S["cellb"]), "Overview and User Guide"],
     [Paragraph("<b>Application</b>", S["cellb"]),
      "ISO 27001 Compliance Auditor v1.0"],
     [Paragraph("<b>Framework</b>", S["cellb"]),
      "ISO/IEC 27001:2022 Annex A (93 controls)"],
     [Paragraph("<b>Stack</b>", S["cellb"]),
      "Python - Streamlit, Pandas, Plotly, FPDF2 - PowerShell 5.1+"],
     [Paragraph("<b>Audience</b>", S["cellb"]),
      "Information security teams, system administrators, internal auditors"],
     [Paragraph("<b>Issued</b>", S["cellb"]), datetime.now().strftime("%d %B %Y")]],
    [34 * mm, 136 * mm], zebra=True)]

F += [NextPageTemplate("Body"), PageBreak()]

# ===========================================================================
# 1. WHAT THE APPLICATION DOES
# ===========================================================================
F += [
    P("1. What this application does", "h1"),
    P("Auditing a system against ISO/IEC 27001 Annex A is normally a manual exercise: an "
      "auditor works through a spreadsheet of controls, interviews administrators, takes "
      "screenshots of settings, and assembles a report by hand. It is slow, it is "
      "inconsistent between auditors, and by the time the report is written the evidence "
      "is already out of date."),
    P("The ISO 27001 Compliance Auditor automates the technical half of that work. A "
      "read-only PowerShell collector inventories a Windows host; the web application "
      "evaluates that evidence against a defined Annex A baseline, assigns a risk level to "
      "every gap, and produces a prioritised remediation roadmap and a management-ready "
      "PDF. What took days of spreadsheet work takes minutes, and the result is repeatable "
      "- the same configuration always yields the same verdict."),

    P("The five capabilities", "h2"),
]

F += [table(
    ["Capability", "What it does"],
    [[Paragraph("<b>Data ingestion</b>", S["cellb"]),
      "Parses system configuration reports in JSON or CSV. Auto-detects layout, coerces "
      "string values into proper types, flattens nested structures into dotted keys and "
      "reports which sections are missing."],
     [Paragraph("<b>Audit engine</b>", S["cellb"]),
      "Cross-references the ingested telemetry against the Annex A baseline, evaluating "
      "every control through declarative checks. Assigns PASS, PARTIAL, FAIL, MANUAL, "
      "NO DATA or N/A, plus a High / Medium / Low risk level."],
     [Paragraph("<b>Compliance dashboard</b>", S["cellb"]),
      "Plotly gauge, status donut, per-theme stacked bars, a radar against a 75% target "
      "and a risk histogram - all recalculating live as attestations change."],
     [Paragraph("<b>Remediation roadmap</b>", S["cellb"]),
      "Orders every gap by risk, groups it into delivery phases with target windows, and "
      "attaches step-by-step technical fixes an administrator can act on directly."],
     [Paragraph("<b>PDF export</b>", S["cellb"]),
      "Generates a professional audit report - scorecard cover, executive summary, theme "
      "breakdown, the full 93-control register, the roadmap and a telemetry appendix."]],
    [30 * mm, 140 * mm])]

F += [
    P("Design principles", "h2"),
    P("Three decisions shape how the tool behaves, and they are worth understanding before "
      "you read a score:"),
    bullets([
        "<b>Absence of evidence is not evidence of compliance.</b> When telemetry for a "
        "control is missing, the control reports NO DATA - never PASS. A collector run "
        "without administrator rights produces a visibly incomplete audit rather than a "
        "misleadingly clean one.",
        "<b>Partial credit is real.</b> A control with six checks where five pass is not "
        "equivalent to one where none pass. PARTIAL carries half weight, so progress is "
        "visible between audits.",
        "<b>Coverage is reported alongside the score.</b> A 100% score derived from three "
        "controls is not a 100% score. The app states what fraction of the 93 controls "
        "produced a real verdict and warns when that fraction is too low to be meaningful.",
    ]),
]

# ===========================================================================
# 2. ARCHITECTURE
# ===========================================================================
F += [PageBreak(), P("2. How it works", "h1")]

F += [
    P("The pipeline has four stages. Each is a separate module, so the audit logic can be "
      "used from a script or a CI job without the web interface."),
]

flow = Table([[
    Paragraph('<b><font color="#ffffff" size=8.5>1. COLLECT</font></b><br/>'
              '<font color="#c7d5ea" size=7>Collect-ISOTelemetry.ps1<br/>'
              'reads Windows config<br/>JSON + CSV out</font>', S["cell"]),
    Paragraph('<font color="#2563af" size=13><b>&rarr;</b></font>', S["cell"]),
    Paragraph('<b><font color="#ffffff" size=8.5>2. INGEST</font></b><br/>'
              '<font color="#c7d5ea" size=7>ingestion.py parses,<br/>'
              'coerces types,<br/>flattens to dotted keys</font>', S["cell"]),
    Paragraph('<font color="#2563af" size=13><b>&rarr;</b></font>', S["cell"]),
    Paragraph('<b><font color="#ffffff" size=8.5>3. AUDIT</font></b><br/>'
              '<font color="#c7d5ea" size=7>audit_engine.py scores<br/>'
              '93 controls, assigns<br/>risk, builds roadmap</font>', S["cell"]),
    Paragraph('<font color="#2563af" size=13><b>&rarr;</b></font>', S["cell"]),
    Paragraph('<b><font color="#ffffff" size=8.5>4. REPORT</font></b><br/>'
              '<font color="#c7d5ea" size=7>Streamlit dashboard<br/>'
              '+ pdf_report.py<br/>audit summary</font>', S["cell"]),
]], colWidths=[36 * mm, 9 * mm, 36 * mm, 9 * mm, 36 * mm, 9 * mm, 35 * mm])
flow.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (0, 0), NAVY),
    ("BACKGROUND", (2, 0), (2, 0), NAVY),
    ("BACKGROUND", (4, 0), (4, 0), NAVY),
    ("BACKGROUND", (6, 0), (6, 0), NAVY),
    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ("TOPPADDING", (0, 0), (-1, -1), 8),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
]))
F += [flow, Spacer(1, 3 * mm),
      P("Figure 1 - The four-stage assessment pipeline.", "caption")]

F += [
    P("The control baseline", "h2"),
    P("The Annex A baseline lives in <font face='Courier' size=8.5>"
      "data/iso27001_baseline.json</font> - a plain data file, not code. Every control "
      "declares its theme, objective, inherent severity, remediation steps and a list of "
      "checks. A check names a telemetry field, an operator and an expected value:"),
    code([
        '{',
        '  "id": "A.8.5",  "title": "Secure authentication",',
        '  "theme": "Technological",  "mode": "automated",  "severity": "High",',
        '  "checks": [',
        '    { "field": "identity.mfa_enabled",      "op": "truthy",',
        '      "label": "Multi-factor authentication enabled" },',
        '    { "field": "identity.lockout_threshold", "op": "gte", "value": 1,',
        '      "label": "Account lockout is enabled" }',
        '  ],',
        '  "remediation": [ "Enforce MFA for all interactive and remote access...", ... ]',
        '}',
    ]),
    P("Because the baseline is declarative you can tune it to your own risk appetite - "
      "raise the minimum password length, add a check against a field your own tooling "
      "emits, or change a severity - without touching the engine. Edit "
      "<font face='Courier' size=8.5>data/build_baseline.py</font> and re-run it to "
      "regenerate the JSON."),
]

F += [
    P("Assessment modes", "h2"),
    P("Not every Annex A control can be measured from a machine. Roughly half are "
      "procedural - whether an incident response plan exists, whether staff sign NDAs. "
      "The baseline is explicit about which is which, so the tool never pretends to have "
      "audited something it cannot see."),
]

F += [table(
    ["Mode", "Controls", "How the verdict is reached"],
    [[Paragraph('<b><font color="#16a34a">Automated</font></b>', S["cellb"]),
      str(MODES["automated"]),
      "Decided purely from telemetry. Example: A.8.7 Protection against malware checks "
      "that anti-malware is enabled, real-time protection is on, signatures are under "
      "three days old, tamper protection is active and at least five ASR rules enforce."],
     [Paragraph('<b><font color="#ca8a04">Hybrid</font></b>', S["cellb"]),
      str(MODES["hybrid"]),
      "Telemetry provides supporting evidence but the control also needs human "
      "confirmation. These cap at PARTIAL until an attestation is recorded - the "
      "technical control may be present while the surrounding process is not."],
     [Paragraph('<b><font color="#2563af">Manual</font></b>', S["cellb"]),
      str(MODES["manual"]),
      "Procedural or physical controls decided entirely by auditor attestation, recorded "
      "in the app or supplied in the telemetry file. Reported as MANUAL until answered."]],
    [24 * mm, 18 * mm, 128 * mm])]

F += [Spacer(1, 2 * mm), KeepTogether([
    P("Annex A coverage by theme", "h2"),
    table(
    ["Theme", "Clause", "Controls", "Representative automated checks"],
    [["Organizational", "A.5", str(THEMES["Organizational"]),
      "Password and lockout policy, dormant accounts, share permissions, log retention, "
      "asset inventory completeness"],
     ["People", "A.6", str(THEMES["People"]),
      "Remote-working posture: disk encryption, managed VPN presence, screen lock timeout"],
     ["Physical", "A.7", str(THEMES["Physical"]),
      "Clear-screen enforcement, off-premises device encryption, TPM presence, removable "
      "media control, disk health"],
     ["Technological", "A.8", str(THEMES["Technological"]),
      "MFA, cryptography, firewall profiles, malware defence, patch currency, audit "
      "policy, backup, application control, TLS versions"]],
    [30 * mm, 16 * mm, 18 * mm, 106 * mm])])]

# ===========================================================================
# 3. SCORING
# ===========================================================================
F += [Spacer(1, 5 * mm), P("3. How scoring works", "h1")]

F += [KeepTogether([
    P("Control statuses", "h2"),
    table(
    ["Status", "Meaning", "Credit"],
    [[Paragraph('<b><font color="#16a34a">PASS</font></b>', S["cellb"]),
      "Every check with usable data was satisfied.", "1.0"],
     [Paragraph('<b><font color="#ca8a04">PARTIAL</font></b>', S["cellb"]),
      "Some checks passed, some failed - the control is partially effective. Also applied "
      "to a hybrid control whose technical checks pass but has no attestation yet.", "0.5"],
     [Paragraph('<b><font color="#dc2626">FAIL</font></b>', S["cellb"]),
      "No check was satisfied. The control is not effective.", "0.0"],
     [Paragraph('<b><font color="#2563af">MANUAL</font></b>', S["cellb"]),
      "A procedural control awaiting attestation.", "excluded"],
     [Paragraph('<b><font color="#64748b">NO DATA</font></b>', S["cellb"]),
      "The telemetry did not contain the fields the control needs - usually an "
      "unelevated collector run.", "excluded"],
     [Paragraph('<b><font color="#64748b">N/A</font></b>', S["cellb"]),
      "Explicitly scoped out by the auditor. Certification requires a documented "
      "justification for each exclusion.", "excluded"]],
    [24 * mm, 126 * mm, 20 * mm])])]

F += [
    P("The weighted score", "h2"),
    P("A flat percentage of passed controls would treat a missing clear-desk policy as "
      "equal to absent disk encryption. Instead each control carries a weight derived from "
      "its inherent severity, so failures on critical controls move the number further:"),
    code([
        '  score  =  SUM(weight x credit)  /  SUM(weight)     x 100',
        '',
        '  credit :  PASS 1.0    PARTIAL 0.5    FAIL 0.0',
        '  weight :  High 5      Medium 3       Low 1',
    ]),
    P("MANUAL and NO DATA controls sit outside the denominator by default, so the score "
      "reflects what was actually assessed. Turning on <b>Strict mode</b> in the sidebar "
      "moves them into the denominator as failures - the conservative posture a "
      "certification auditor would take, and a useful worst-case view."),

    Paragraph(
        "<b>Coverage matters as much as score.</b> The app reports assessment coverage - "
        "the share of the 93 controls that produced a real verdict - next to the headline "
        "figure. Below 25% it refuses to award a maturity rating and prints a caveat on "
        "the PDF cover, because a high score drawn from a handful of controls tells you "
        "almost nothing.", S["note"]),

    P("Risk levels", "h2"),
    P("A failed control inherits its severity as the open risk level. A partially "
      "implemented High severity control steps down to Medium, on the basis that a "
      "partially mitigated risk is a smaller risk than an unmitigated one. Passed and "
      "scoped-out controls carry no risk."),
]

F += [KeepTogether([
    P("Maturity bands", "h2"),
    table(
    ["Weighted score", "Maturity rating"],
    [["90 - 100%", "Optimised - certification ready"],
     ["75 - 89%", "Managed - minor gaps"],
     ["55 - 74%", "Defined - material gaps"],
     ["35 - 54%", "Developing - significant remediation required"],
     ["Below 35%", "Initial - critical exposure"]],
    [32 * mm, 138 * mm])])]

# ===========================================================================
# 4. INSTALLING AND RUNNING
# ===========================================================================
F += [Spacer(1, 5 * mm), P("4. Installing and running the web app", "h1")]

F += [
    P("Requirements", "h2"),
    bullets([
        "Python 3.9 or later on the machine running the app (any OS - Windows, macOS, Linux).",
        "Windows PowerShell 5.1 or PowerShell 7+ on each host you want to audit.",
        "No database, no server, no internet connection. Everything runs locally and no "
        "telemetry leaves the machine.",
    ]),
    P("Installation", "h2"),
    code([
        'cd ISO27001',
        'pip install -r requirements.txt',
        'streamlit run app/dashboard.py',
    ]),
    P("On macOS and Linux, <font face='Courier' size=8.5>./run.sh</font> does the same "
      "thing but creates an isolated virtual environment first and rebuilds the baseline "
      "if you have edited the generator. The app opens at "
      "<font face='Courier' size=8.5>http://localhost:8501</font>."),

    P("Trying it without a Windows host", "h2"),
    P("Three sample profiles ship with the app. Pick one from the sidebar dropdown and "
      "press Load - no collection needed. They are the fastest way to understand what the "
      "output looks like at different levels of maturity:"),
]

demo_rows = []
for fname, label in (("hardened_server.json", "Well-managed Windows Server 2022"),
                     ("mixed_endpoint.csv", "Partly hardened Windows 11 laptop (CSV)"),
                     ("legacy_workstation.json", "Neglected Windows 10 workstation")):
    r = DEMO[fname]
    colour = GREEN if r["compliance_score"] >= 75 else (
        AMBER if r["compliance_score"] >= 40 else RED)
    demo_rows.append([
        Paragraph(f"<font face='Courier' size=7.6>{fname}</font>", S["cell"]),
        label,
        Paragraph(f'<b><font color="#{colour.hexval()[2:]}">'
                  f'{r["compliance_score"]}%</font></b>', S["cellb"]),
        str(r["counts"]["PASS"]),
        str(r["counts"]["FAIL"] + r["counts"]["PARTIAL"]),
        str(r["risk_counts"]["High"]),
    ])

F += [table(
    ["Sample file", "Profile", "Score", "Pass", "Gaps", "High risk"],
    demo_rows,
    [42 * mm, 60 * mm, 18 * mm, 15 * mm, 16 * mm, 19 * mm])]
F += [P("Figure 2 - Results produced by the bundled sample profiles.", "caption")]

F += [
    P("The five tabs", "h2"),
]
F += [table(
    ["Tab", "What you do there"],
    [[Paragraph("<b>Dashboard</b>", S["cellb"]),
      "Read the headline position: compliance gauge, status donut, per-theme bars, a "
      "radar against a 75% target, risk histogram and cards for the top six findings."],
     [Paragraph("<b>Control register</b>", S["cellb"]),
      "All 93 controls, filterable by theme, status and risk and searchable by ID or "
      "title. Select any control to see each individual check - the field queried, the "
      "rule applied, the value observed - plus its full remediation guidance."],
     [Paragraph("<b>Remediation roadmap</b>", S["cellb"]),
      "Every gap ordered by risk and grouped into phases, each expandable to reveal the "
      "failed checks and numbered technical fixes. Exports to CSV for your ticket system."],
     [Paragraph("<b>Manual attestations</b>", S["cellb"]),
      "Answer the procedural controls. Results update immediately. Answers export to "
      "JSON so the next audit of the same organisation starts where this one finished. "
      "Scope exclusions are recorded here too."],
     [Paragraph("<b>Evidence</b>", S["cellb"]),
      "Every ingested parameter with its value, type and source section - the raw "
      "evidence behind each verdict, searchable and exportable."],
     [Paragraph("<b>Export</b>", S["cellb"]),
      "Build the PDF audit report with selectable sections, or download the register as "
      "CSV and the full results as JSON."]],
    [32 * mm, 138 * mm])]

# ===========================================================================
# 5. THE COLLECTOR
# ===========================================================================
F += [Spacer(1, 5 * mm), section(
    "5. Collecting telemetry with PowerShell",
    P("<font face='Courier' size=8.5>collector/Collect-ISOTelemetry.ps1</font> performs a "
      "read-only inventory of a Windows endpoint or server and writes a configuration "
      "report in the schema the app expects. It changes no setting, installs nothing and "
      "opens no outbound connection. Every probe is individually wrapped, so a failure on "
      "one item degrades that single value to \"not collected\" rather than aborting the run."))]

F += [
    P("Basic use", "h2"),
    code([
        '# Open PowerShell as Administrator on the target host',
        'Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force',
        '.\\Collect-ISOTelemetry.ps1',
    ]),
    P("This writes <font face='Courier' size=8.5>ISOTelemetry_&lt;HOST&gt;_&lt;timestamp&gt;"
      ".json</font> and a matching <font face='Courier' size=8.5>.csv</font> to the current "
      "folder. Upload the JSON in the web app - it is the richer of the two."),

    Paragraph(
        "<b>Run it elevated.</b> Without administrator rights the BitLocker, audit policy, "
        "Defender and firewall probes return nothing, and the affected controls report NO "
        "DATA. That is the safe behaviour - the tool will not guess - but it leaves you "
        "with a materially incomplete audit. The script warns you at startup when it is "
        "not elevated.", S["note"]),

    P("Parameters", "h2"),
]

F += [table(
    ["Parameter", "Purpose"],
    [[Paragraph("<font face='Courier' size=7.8>-OutputPath</font>", S["cell"]),
      "Directory for the reports. Created if it does not exist. Defaults to the current folder."],
     [Paragraph("<font face='Courier' size=7.8>-Format</font>", S["cell"]),
      "Json, Csv or Both (default). Use Csv only where tooling cannot handle JSON."],
     [Paragraph("<font face='Courier' size=7.8>-IncludeAttestations</font>", S["cell"]),
      "Adds an empty attestations block to the JSON so an auditor can pre-fill the "
      "procedural control answers before uploading."],
     [Paragraph("<font face='Courier' size=7.8>-ApprovedSoftware</font>", S["cell"]),
      "Path to a text file of approved application names, one per line. Anything installed "
      "and not on the list is reported as unauthorised software. Without it the script "
      "falls back to a built-in list of commonly-flagged remote access and network tools."],
     [Paragraph("<font face='Courier' size=7.8>-Quiet</font>", S["cell"]),
      "Suppresses console output. Use for scheduled or fleet-wide runs."]],
    [42 * mm, 128 * mm])]

F += [
    P("Auditing a fleet", "h2"),
    P("The script returns the paths it wrote, so it composes in a pipeline. Over WinRM:"),
    code([
        'Get-Content .\\hosts.txt | ForEach-Object {',
        '    Invoke-Command -ComputerName $_ -FilePath .\\Collect-ISOTelemetry.ps1',
        '}',
    ]),
    P("Or as a scheduled task writing to a central share, giving you a rolling record of "
      "configuration drift across the estate:"),
    code([
        '.\\Collect-ISOTelemetry.ps1 -OutputPath \\\\fileserver\\audit$ -Quiet',
    ]),

    P("What it collects", "h2"),
    P("Around 170 parameters across thirteen sections. The pre-flight summary printed at "
      "the end flags the headline problems immediately, before you even open the app."),
]

F += [table(
    ["Section", "Examples of what is captured"],
    [["metadata", "Hostname, OS caption and build, domain membership, serial number, "
                  "collection timestamp, whether the run was elevated"],
     ["identity", "MFA providers, local administrator count and membership, password "
                  "policy, lockout policy, dormant accounts, LAPS, Credential Guard"],
     ["encryption", "BitLocker status and algorithm, key protectors, recovery key escrow, "
                    "TLS/SSL protocol versions, SMB signing, SMBv1, FIPS mode"],
     ["logging", "Advanced audit policy per subcategory, Security log size and retention, "
                 "PowerShell script block logging, command-line auditing, SIEM agents, "
                 "time source and clock offset"],
     ["endpoint_protection", "Defender state, signature age, tamper protection, ASR rule "
                             "count, EDR presence, firewall profiles, Secure Boot, TPM, "
                             "UAC, AppLocker/WDAC, USB control, screen lock"],
     ["patching", "Automatic update state, days since last patch, missing critical "
                  "updates, pending reboot, OS support status, WSUS server"],
     ["network", "RDP and NLA, listening ports, high-risk ports, open shares and "
                 "'Everyone' permissions, NetBIOS, LLMNR, DNS servers, VPN presence"],
     ["backup", "Backup product and last successful run, shadow copies, system restore"],
     ["asset", "Installed software inventory, unauthorised software, asset tag and owner, "
               "classification labelling, DLP, MDM enrolment"],
     ["services / configuration", "Unnecessary running services, Telnet, Remote Registry, "
                                  "and a computed count of hardening baseline drift items"],
     ["capacity / hardware", "Disk and memory headroom, CPU load, physical disk health"]],
    [34 * mm, 136 * mm])]

F += [
    P("What it deliberately does not collect", "h2"),
    P("Backup encryption, off-site or immutable copies and restore-test recency are not "
      "discoverable from a local host - they live in the backup platform. The collector "
      "emits them as null so the related controls report NO DATA, and you record the real "
      "answer as an attestation. MFA is inferred from installed credential providers, "
      "which will miss some third-party products; confirm it by attestation if your MFA "
      "solution is not detected."),
]

# ===========================================================================
# 6. WALKTHROUGH
# ===========================================================================
F += [Spacer(1, 5 * mm), P("6. A complete audit, start to finish", "h1")]

F += [numbered([
    "<b>Collect.</b> On the target host, open PowerShell as Administrator and run "
    "<font face='Courier' size=8.3>.\\Collect-ISOTelemetry.ps1 -IncludeAttestations</font>. "
    "Read the pre-flight summary - it flags missing encryption, absent anti-malware, "
    "disabled lockout and missing patches before you go any further.",

    "<b>Load.</b> Start the web app, choose the JSON file in the sidebar and press Load. "
    "Set the organisation name and the 'Prepared by' field now - both appear on the PDF.",

    "<b>Read the headline.</b> The Dashboard gives you the weighted score, the maturity "
    "band and the count of open high risks. Check the assessment coverage figure "
    "underneath the gauge: if it is low, the collector probably ran unelevated and you "
    "should collect again before drawing conclusions.",

    "<b>Attest.</b> Open Manual attestations and work through the procedural controls. "
    "This is the part only a human can do, and it is where the score becomes "
    "representative rather than merely technical. Export your answers to JSON when done - "
    "the next audit of the same organisation can import them and start from there.",

    "<b>Scope.</b> If a control genuinely does not apply - no in-house development, so "
    "the secure coding controls are out of scope - mark it Not Applicable at the bottom "
    "of the attestations tab. Certification requires a documented justification for every "
    "exclusion, so record yours in the scope statement.",

    "<b>Investigate.</b> Use the Control register to examine anything surprising. Each "
    "control shows the individual checks, the exact telemetry field queried, the rule "
    "applied and the value observed - so a disputed finding can be settled against "
    "evidence rather than opinion.",

    "<b>Plan.</b> The Remediation roadmap orders every gap by risk and groups it into "
    "phases. Phase 1 is your immediate 30-day queue. Expand any item for the numbered "
    "technical steps, and export the roadmap as CSV to load into your ticketing system.",

    "<b>Report.</b> On the Export tab write a short scope and limitations statement, "
    "choose which sections to include and build the PDF. Download the register CSV and "
    "results JSON alongside it as your evidence pack.",

    "<b>Re-audit.</b> After remediation, collect again and compare. Because the baseline "
    "is fixed and the engine is deterministic, the difference in score is a real measure "
    "of progress rather than a difference of auditor opinion.",
])]

F += [
    P("What the exported PDF contains", "h2"),
]
F += [table(
    ["Section", "Contents"],
    [["Cover", "Scorecard with weighted compliance, pass and fail counts, open high "
               "risks, a compliance bar, assessment metadata and your scope statement"],
     ["1. Executive summary", "Narrative of the result, how the score was derived, the "
                              "open risk profile and a status distribution table"],
     ["2. Compliance by theme", "Per-theme table and bars, plus the highest-impact open "
                                "findings"],
     ["3. Control register", "All 93 controls with theme, mode, status, risk and checks "
                             "passed"],
     ["4. Remediation roadmap", "Prioritised summary with target windows"],
     ["5. Technical detail", "Failed checks and numbered fix steps for the top findings"],
     ["Appendix A", "The telemetry parameters that constitute the evidence base"]],
    [40 * mm, 130 * mm])]

# ===========================================================================
# 7. TROUBLESHOOTING & LIMITATIONS
# ===========================================================================
F += [Spacer(1, 5 * mm), P("7. Troubleshooting", "h1")]

F += [table(
    ["Symptom", "Cause and resolution"],
    [[Paragraph("<b>Many controls show NO DATA</b>", S["cellb"]),
      "The collector ran without administrator rights, so the BitLocker, audit policy, "
      "Defender and firewall probes returned nothing. Re-run PowerShell elevated. Check "
      "the <font face='Courier' size=7.6>metadata.collected_elevated</font> field in the "
      "Evidence tab to confirm."],
     [Paragraph("<b>Score looks implausibly high</b>", S["cellb"]),
      "Check assessment coverage on the Dashboard. A high score from a small assessed "
      "pool is not meaningful - the app warns when coverage drops below 50%. Record "
      "attestations, or enable Strict mode to see the worst case."],
     [Paragraph("<b>'Could not parse the file'</b>", S["cellb"]),
      "The uploaded file is not valid JSON, or the CSV lacks a recognised layout. CSV "
      "must be either key/value columns or one header row of dotted keys plus one data "
      "row. Re-run the collector rather than hand-editing the report."],
     [Paragraph("<b>A control passes that should not</b>", S["cellb"]),
      "Open it in the Control register and read the individual checks - the observed "
      "value is shown for each. If the baseline is too permissive for your risk appetite, "
      "tighten the check in <font face='Courier' size=7.6>data/build_baseline.py</font> "
      "and re-run it."],
     [Paragraph("<b>MFA reported as absent</b>", S["cellb"]),
      "MFA is inferred from installed credential providers and will miss some third-party "
      "products. Confirm the real position and record it as an attestation."],
     [Paragraph("<b>Script blocked from running</b>", S["cellb"]),
      "PowerShell execution policy. Run <font face='Courier' size=7.6>Set-ExecutionPolicy "
      "-Scope Process -ExecutionPolicy Bypass -Force</font> first; this affects only the "
      "current session."],
     [Paragraph("<b>PDF build fails</b>", S["cellb"]),
      "Ensure <font face='Courier' size=7.6>fpdf2</font> is installed, not the abandoned "
      "<font face='Courier' size=7.6>fpdf</font> package: "
      "<font face='Courier' size=7.6>pip uninstall fpdf &amp;&amp; pip install fpdf2</font>."]],
    [38 * mm, 132 * mm])]

F += [
    P("8. Limitations and honest caveats", "h1"),
    P("It is worth being clear about what this tool is and is not, because overstating an "
      "automated result is the fastest way to fail a real certification audit."),
    bullets([
        "<b>This is a technical configuration assessment, not an ISMS audit.</b> "
        "ISO/IEC 27001 certification assesses a management system - clauses 4 to 10 cover "
        "context, leadership, planning, risk treatment, competence and continual "
        "improvement. None of that is in Annex A, and none of it is measurable from a "
        "registry key. The tool supports certification work; it does not substitute for it.",

        "<b>It audits one host at a time.</b> A clean result on one server says nothing "
        "about the other forty. Collect across the estate and treat each report as one "
        "sample.",

        "<b>Point-in-time evidence.</b> Configuration drifts. A report is accurate for the "
        "moment it was collected and no longer.",

        "<b>Detection heuristics are imperfect.</b> MFA, DLP, EDR and backup products are "
        "identified by service names and registry markers. A product the heuristic does "
        "not recognise will be reported as absent - verify by attestation.",

        "<b>Attestations are self-reported.</b> The tool records what an auditor asserts; "
        "it cannot verify it. For certification, back each attestation with documented "
        "evidence.",

        "<b>The baseline reflects a defensible interpretation, not the standard's text.</b> "
        "ISO 27001 states control objectives, not specific thresholds. The decision that "
        "passwords must be 14 characters, or signatures under three days old, is a "
        "judgement drawn from CIS and Microsoft security baselines. Your certification "
        "body may take a different view; the baseline is editable for exactly that reason.",
    ]),
]

F += [
    Spacer(1, 3 * mm),
    Paragraph(
        "<b>In short:</b> use this tool to find and fix technical gaps quickly, to track "
        "measurable progress between audits, and to arrive at a certification audit with "
        "the configuration evidence already assembled. Do not present its score as a "
        "statement of ISO 27001 compliance.", S["note"]),
]

if __name__ == "__main__":
    doc.build(F)
    size = os.path.getsize(OUT)
    print(f"Wrote {OUT}  ({size/1024:.0f} KB)")
