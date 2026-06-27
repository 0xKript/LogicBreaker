"""
PDF report generator
====================

Renders the scan as a clean, human-readable PDF using reportlab (Platypus).
Mirrors the HTML report: a plain-language summary, a severity legend that says
what each level means, and one block per finding explaining -- in plain words --
what the problem is, what an attacker could do, and how to fix it. Technical
detail (CWE, confidence, example attack, code) follows in a muted style.
"""

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, HRFlowable, Preformatted, KeepTogether)

from reporting.explain import severity_meaning, status_meaning

SEV = {
    "CRITICAL": colors.HexColor("#d6336c"),
    "HIGH": colors.HexColor("#e8590c"),
    "MEDIUM": colors.HexColor("#f08c00"),
    "LOW": colors.HexColor("#1c7ed6"),
}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
INK = colors.HexColor("#1b1f24")
MUTED = colors.HexColor("#646c76")
ACCENT = colors.HexColor("#2563eb")
GREEN = colors.HexColor("#2f9e44")
STATUS_COLOR = {
    "VERIFIED_FIX": GREEN, "LANGUAGE_PATCH": GREEN, "LLM_FIX": ACCENT,
    "CONFIRMED": colors.HexColor("#d6336c"), "AUTO_FIX_FAILED": colors.HexColor("#e8590c"),
    "LEFT_UNFIXED": MUTED, "RECOMMENDATION": MUTED,
}
STATUS_LABEL = {
    "VERIFIED_FIX": "Fixed & verified", "LANGUAGE_PATCH": "Fixed",
    "LLM_FIX": "AI fix (review)", "CONFIRMED": "Not fixed",
    "AUTO_FIX_FAILED": "Needs manual fix", "LEFT_UNFIXED": "Left as-is",
    "RECOMMENDATION": "Manual fix needed",
}


def _e(s):
    from xml.sax.saxutils import escape
    return escape(str(s) if s is not None else "")


def _lang(k):
    try:
        from languages.registry import display_name
        return display_name(k)
    except Exception:
        return k


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("Brand", parent=ss["Normal"], fontName="Helvetica-Bold",
                          fontSize=9, textColor=ACCENT, spaceAfter=2, leading=11))
    ss.add(ParagraphStyle("TitleX", parent=ss["Title"], fontName="Helvetica-Bold",
                          fontSize=22, textColor=INK, spaceAfter=2, alignment=TA_LEFT, leading=26))
    ss.add(ParagraphStyle("SubX", parent=ss["Normal"], fontSize=9, textColor=MUTED, spaceAfter=12))
    ss.add(ParagraphStyle("Headline", parent=ss["Normal"], fontSize=11, textColor=INK,
                          leading=16, spaceBefore=4, spaceAfter=4))
    ss.add(ParagraphStyle("H2X", parent=ss["Heading2"], fontName="Helvetica-Bold",
                          fontSize=11, textColor=MUTED, spaceBefore=20, spaceAfter=8, leading=13))
    ss.add(ParagraphStyle("FType", parent=ss["Normal"], fontName="Helvetica-Bold",
                          fontSize=12.5, textColor=INK, spaceAfter=2, leading=15))
    ss.add(ParagraphStyle("Loc", parent=ss["Normal"], fontName="Courier",
                          fontSize=8, textColor=MUTED, spaceAfter=6, leading=11))
    ss.add(ParagraphStyle("Key", parent=ss["Normal"], fontName="Helvetica-Bold",
                          fontSize=9, textColor=MUTED, leading=13))
    ss.add(ParagraphStyle("Val", parent=ss["Normal"], fontSize=10, textColor=INK,
                          leading=14, spaceAfter=1))
    ss.add(ParagraphStyle("Small", parent=ss["Normal"], fontSize=8.5, textColor=MUTED, leading=12))
    ss.add(ParagraphStyle("Legend", parent=ss["Normal"], fontSize=9.5, textColor=INK, leading=13))
    ss.add(ParagraphStyle("CodeWrap", parent=ss["Normal"], fontName="Courier", fontSize=7.5,
                          textColor=colors.HexColor("#d7dde5"), leading=10.5, wordWrap="CJK"))
    return ss


def generate(report_data, output_path):
    ss = _styles()
    meta = report_data["meta"]
    stats = report_data["stats"]
    findings = report_data["findings"]
    dynamic = report_data.get("dynamic", [])
    patches = report_data.get("patches", [])

    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=16*mm, bottomMargin=16*mm,
                            title="LogicBreaker AI Security Report")
    story = []

    story.append(Paragraph("LOGICBREAKER AI", ss["Brand"]))
    story.append(Paragraph("Security Report", ss["TitleX"]))
    story.append(Paragraph(
        f"{_e(meta['target'])} &nbsp;|&nbsp; {meta['generated']} &nbsp;|&nbsp; "
        f"{stats.get('analysable', 0)} files analysed &nbsp;|&nbsp; "
        f"{meta['mode']} ({meta.get('provider','no AI')})", ss["SubX"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#d0d7de")))
    story.append(Spacer(1, 8))

    sev_counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    verified = sum(1 for p in patches if p.get("status") == "VERIFIED_FIX")

    # plain-language headline
    story.append(Paragraph(_headline(len(findings), sev_counts, verified), ss["Headline"]))
    story.append(Spacer(1, 10))

    # severity count strip
    story.append(_count_strip(sev_counts))
    story.append(Spacer(1, 6))

    # severity legend (what each level means)
    leg = _legend_table(sev_counts, ss)
    if leg:
        story.append(leg)

    # findings
    story.append(Paragraph("Findings", ss["H2X"]))
    patch_by = {}
    for p in patches:
        patch_by.setdefault((p.get("finding_type", ""), p.get("file", "")), p)

    if not findings:
        story.append(Paragraph("No security issues were found in the analysed code.", ss["Val"]))
    else:
        ordered = sorted(findings, key=lambda x: SEV_ORDER.index(x["severity"])
                         if x["severity"] in SEV_ORDER else 99)
        for f in ordered:
            story.append(_finding_block(f, patch_by, ss))

    # live tests
    if dynamic:
        story.append(Paragraph("Live exploit tests", ss["H2X"]))
        story.append(Paragraph("These issues were tested against a running copy of the app to "
                               "confirm they are real.", ss["Small"]))
        story.append(Spacer(1, 6))
        for d in dynamic:
            story.append(_dynamic_block(d, ss))

    doc.build(story)
    return output_path


# ---- summary pieces ------------------------------------------------------

def _headline(total, sev, verified):
    if total == 0:
        return "No security issues were found in the code that was analysed."
    parts = []
    if sev["CRITICAL"]:
        parts.append(f"<b>{sev['CRITICAL']} critical</b> (fix immediately)")
    if sev["HIGH"]:
        parts.append(f"<b>{sev['HIGH']} high</b>")
    if sev["MEDIUM"]:
        parts.append(f"{sev['MEDIUM']} medium")
    if sev["LOW"]:
        parts.append(f"{sev['LOW']} low")
    line = f"We found <b>{total}</b> security {'issue' if total == 1 else 'issues'}: " + ", ".join(parts) + ". "
    if sev["CRITICAL"]:
        line += "The critical issues let an attacker take over the system or reach all your data, so start with those."
    elif sev["HIGH"]:
        line += "The high issues could let an attacker steal data, so address them first."
    else:
        line += "None are critical, but each one is worth fixing."
    if verified:
        line += f" {verified} {'issue was' if verified == 1 else 'issues were'} fixed automatically and re-tested."
    return line


def _count_strip(sev):
    cells = []
    for s in SEV_ORDER:
        cells.append([Paragraph(f"<b>{sev[s]}</b>", ParagraphStyle(
            "n", fontName="Helvetica-Bold", fontSize=20, textColor=SEV[s], alignment=1, leading=22)),
            Paragraph(s.title(), ParagraphStyle("l", fontSize=8, textColor=MUTED, alignment=1))])
    data = [[c[0] for c in cells], [c[1] for c in cells]]
    t = Table(data, colWidths=[44*mm]*4)
    t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e4e8ec")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e4e8ec")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, 0), 8), ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
    ]))
    return t


def _legend_table(sev, ss):
    rows = []
    for s in SEV_ORDER:
        if sev[s] == 0:
            continue
        chip = Paragraph(f"<font color='#{SEV[s].hexval()[2:]}'>●</font> <b>{s.title()}</b>", ss["Legend"])
        rows.append([chip, Paragraph(severity_meaning(s), ss["Legend"])])
    if not rows:
        return None
    t = Table(rows, colWidths=[30*mm, 146*mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#eef1f4")),
    ]))
    return t


# ---- finding block -------------------------------------------------------

def _chip(text, color, ss):
    p = Paragraph(f"<font color='white'><b>{_e(text)}</b></font>", ss["Small"])
    t = Table([[p]], colWidths=[24*mm], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
    ]))
    return t


def _kv(key, val, ss):
    """A two-column key/value row used inside a finding."""
    t = Table([[Paragraph(_e(key), ss["Key"]), Paragraph(_e(val), ss["Val"])]],
              colWidths=[26*mm, 150*mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (0, 0), 0),
    ]))
    return t


def _finding_block(f, patch_by, ss):
    sev = f["severity"]
    color = SEV.get(sev, MUTED)
    # Use each finding's OWN explanation (AI model's words for AI findings, the
    # knowledge base for engine findings) -- no hard-coded per-type catalogue.
    what = f.get("explanation", "")
    risk = f.get("impact", "")
    howfix = f.get("remediation", "")

    loc = f"{f['file']} · line {f['lineno']} · {_lang(f['language'])}"
    if f.get("function"):
        loc = f"{f['file']} · in {f['function']}() · line {f['lineno']} · {_lang(f['language'])}"

    elems = [
        _chip(sev.title(), color, ss),
        Spacer(1, 3),
        Paragraph(_e(f["type"]), ss["FType"]),
        Paragraph(_e(loc), ss["Loc"]),
        _kv("What it is", what, ss),
    ]
    if risk:
        elems.append(_kv("The risk", risk, ss))
    if howfix:
        elems.append(_kv("How to fix", howfix, ss))

    patch = patch_by.get((f.get("type", ""), f.get("file", "")))
    if patch:
        st = patch.get("status", "RECOMMENDATION")
        sc = STATUS_COLOR.get(st, MUTED)
        label = STATUS_LABEL.get(st, st)
        fixp = Paragraph(f"<font color='#{sc.hexval()[2:]}'><b>{_e(label)}</b></font> — "
                         f"{_e(status_meaning(st))}", ss["Val"])
        t = Table([[Paragraph("Fix status", ss["Key"]), fixp]], colWidths=[26*mm, 150*mm])
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("TOPPADDING", (0, 0), (-1, -1), 2),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                               ("LEFTPADDING", (0, 0), (0, 0), 0)]))
        elems.append(t)

    # technical detail (muted)
    elems.append(Spacer(1, 3))
    tech = f"CWE: {f.get('cwe','')}  |  detection confidence: {int(f.get('confidence',0)*100)}%"
    if f.get("dynamic_proof") and f["dynamic_proof"].get("vulnerable"):
        tech += "  |  confirmed by live test"
    elems.append(Paragraph(_e(tech), ss["Small"]))
    if f.get("exploit_scenario"):
        elems.append(Paragraph(f"<b>Example attack:</b> {_e(f['exploit_scenario'])}", ss["Small"]))
    if f.get("source"):
        elems.append(Spacer(1, 3))
        elems.append(_code_box(f["source"][:900], ss))

    elems.append(Spacer(1, 4))
    elems.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#eef1f4")))
    elems.append(Spacer(1, 8))
    return KeepTogether(elems)


def _code_box(code, ss):
    t = Table([[Preformatted(code, ss["CodeWrap"])]], colWidths=[176*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0d1117")),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    return t


def _dynamic_block(d, ss):
    vuln = d.get("vulnerable")
    color = SEV["CRITICAL"] if vuln else SEV["LOW"]
    label = "Exploited" if vuln else "Safe (not exploited)"
    elems = [
        _chip(label, color, ss),
        Spacer(1, 3),
        Paragraph(_e(d.get("matched_finding_type", d.get("probe", "test"))), ss["FType"]),
        _kv("What happened", _proof_summary(d), ss),
        Spacer(1, 6),
    ]
    return KeepTogether(elems)


def _proof_summary(dp):
    p = dp.get("probe")
    if p == "race_condition":
        return (f"On {dp.get('endpoint')}, we sent {dp.get('requests_sent')} requests at once; "
                f"{dp.get('successful_actions')} went through when only {dp.get('expected_actions')} should have "
                f"(value moved {dp.get('initial_value')} to {dp.get('final_value')}).")
    if p == "idor":
        return f"On {dp.get('endpoint')}, two different record ids returned other users' data with no login."
    if p == "sql_injection":
        return (f"On {dp.get('endpoint')}, an injection payload returned {dp.get('rows_tautology')} rows "
                f"instead of {dp.get('rows_benign')} — proof the query was manipulated.")
    if dp.get("note"):
        return dp["note"]
    return "A live test was run against this endpoint."
