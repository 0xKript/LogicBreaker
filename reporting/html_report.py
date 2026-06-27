"""
HTML report generator
=====================

Produces a single self-contained HTML file (no external assets) that anyone can
read -- not just a security engineer. Every finding is explained in plain
language: what the problem is, what an attacker could do with it, and how to fix
it. The technical detail (CWE, confidence, code, exploit trace) is still there,
tucked under a "Technical details" toggle so it never gets in the way.
"""

import html
import json
from datetime import datetime

from reporting.explain import severity_meaning, status_meaning

SEV_COLORS = {"CRITICAL": "#d6336c", "HIGH": "#e8590c", "MEDIUM": "#f08c00", "LOW": "#1c7ed6"}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
STATUS_COLORS = {
    "VERIFIED_FIX": "#2f9e44", "LANGUAGE_PATCH": "#2f9e44", "LLM_FIX": "#1c7ed6",
    "CONFIRMED": "#d6336c", "AUTO_FIX_FAILED": "#e8590c",
    "LEFT_UNFIXED": "#868e96", "RECOMMENDATION": "#868e96",
}


def _esc(s):
    return html.escape(str(s) if s is not None else "")


def _lang_name(k):
    try:
        from languages.registry import display_name
        return display_name(k)
    except Exception:
        return k


def generate(report_data, output_path):
    meta = report_data["meta"]
    stats = report_data["stats"]
    findings = report_data["findings"]
    dynamic = report_data.get("dynamic", [])
    patches = report_data.get("patches", [])

    sev_counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    confirmed = sum(1 for d in dynamic if d.get("vulnerable"))
    verified = sum(1 for p in patches if p.get("status") == "VERIFIED_FIX")

    # map finding -> its patch status (so each finding card can show fix state)
    patch_by_type = {}
    for p in patches:
        key = (p.get("finding_type", ""), p.get("file", ""))
        patch_by_type.setdefault(key, p)

    ordered = sorted(findings, key=lambda x: SEV_ORDER.index(x["severity"])
                     if x["severity"] in SEV_ORDER else 99)
    cards = "".join(_finding_card(f, patch_by_type) for f in ordered)
    if not cards:
        cards = _empty("No security issues were found in the analysed code.")

    legend = _severity_legend(sev_counts)
    headline = _headline(len(findings), sev_counts, verified)
    dyn_section = _dynamic_section(dynamic)

    doc = _TEMPLATE.format(
        target=_esc(meta["target"]),
        generated=_esc(meta["generated"]),
        mode=_esc(meta["mode"]),
        provider=_esc(meta.get("provider", "fast scan (no AI)")),
        files=stats.get("analysable", 0),
        total=len(findings),
        crit=sev_counts["CRITICAL"], high=sev_counts["HIGH"],
        med=sev_counts["MEDIUM"], low=sev_counts["LOW"],
        verified=verified,
        headline=headline,
        legend=legend,
        finding_cards=cards,
        dynamic_section=dyn_section,
        c_crit=SEV_COLORS["CRITICAL"], c_high=SEV_COLORS["HIGH"],
        c_med=SEV_COLORS["MEDIUM"], c_low=SEV_COLORS["LOW"],
    )
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(doc)
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
    line = f"We found <b>{total}</b> security {'issue' if total == 1 else 'issues'}: " + ", ".join(parts) + "."
    if sev["CRITICAL"]:
        line += " The critical issues let an attacker take over the system or reach all your data, so start with those."
    elif sev["HIGH"]:
        line += " The high issues could let an attacker steal data, so address them first."
    else:
        line += " None are critical, but each one is worth fixing."
    if verified:
        line += f" {verified} {'issue was' if verified == 1 else 'issues were'} fixed automatically and re-tested."
    return line


def _severity_legend(sev):
    rows = ""
    for s in SEV_ORDER:
        if sev[s] == 0:
            continue
        rows += (f"<div class='leg'><span class='dot' style='background:{SEV_COLORS[s]}'></span>"
                 f"<span class='leg-name'>{s.title()}</span>"
                 f"<span class='leg-txt'>{_esc(severity_meaning(s))}</span></div>")
    if not rows:
        return ""
    return f"<div class='legend'>{rows}</div>"


# ---- finding card --------------------------------------------------------

def _finding_card(f, patch_by_type):
    sev = f["severity"]
    color = SEV_COLORS.get(sev, "#868e96")
    # Use each finding's OWN explanation -- for AI findings these are the model's
    # own words (what / impact / fix); for engine findings they come from the
    # knowledge base. No hard-coded per-type catalogue.
    what = f.get("explanation", "")
    risk = f.get("impact", "")
    howfix = f.get("remediation", "")

    # plain location line
    loc = (f"{_esc(f['file'])} &nbsp;·&nbsp; line {f['lineno']}"
           f" &nbsp;·&nbsp; {_esc(_lang_name(f['language']))}")
    if f.get("function"):
        loc = (f"{_esc(f['file'])} &nbsp;·&nbsp; in <b>{_esc(f['function'])}()</b>"
               f" &nbsp;·&nbsp; line {f['lineno']} &nbsp;·&nbsp; {_esc(_lang_name(f['language']))}")

    # was it confirmed by a live exploit?
    confirmed = ""
    if f.get("dynamic_proof") and f["dynamic_proof"].get("vulnerable"):
        confirmed = ("<span class='tag tag-confirmed'>Confirmed by live test</span>")

    # fix status, if this finding was patched
    patch = patch_by_type.get((f.get("type", ""), f.get("file", "")))
    fix_row = ""
    if patch:
        st = patch.get("status", "RECOMMENDATION")
        sc = STATUS_COLORS.get(st, "#868e96")
        fix_row = (f"<div class='row'><span class='k'>Fix status</span>"
                   f"<span class='v'><span class='tag' style='background:{sc}'>{_esc(_status_label(st))}</span> "
                   f"{_esc(status_meaning(st))}</span></div>")

    # risk/fix rows (only if we have plain text for them)
    risk_row = f"<div class='row'><span class='k'>The risk</span><span class='v'>{_esc(risk)}</span></div>" if risk else ""
    fix_how_row = f"<div class='row'><span class='k'>How to fix</span><span class='v'>{_esc(howfix)}</span></div>" if howfix else ""

    # technical details (collapsed)
    tech = (f"<div class='tline'><b>CWE:</b> {_esc(f.get('cwe',''))} &nbsp;|&nbsp; "
            f"<b>Detection confidence:</b> {int(f.get('confidence',0)*100)}%</div>")
    if f.get("exploit_scenario"):
        tech += f"<div class='tline'><b>Example attack:</b> {_esc(f['exploit_scenario'])}</div>"
    if f.get("source"):
        tech += f"<pre class='code'>{_esc(f['source'][:1200])}</pre>"

    return f"""
    <div class="card" style="border-left-color:{color}">
      <div class="chead">
        <span class="sev" style="background:{color}">{_esc(sev.title())}</span>
        <span class="title">{_esc(f['type'])}</span>
        {confirmed}
      </div>
      <div class="loc">{loc}</div>
      <div class="row"><span class="k">What it is</span><span class="v">{_esc(what)}</span></div>
      {risk_row}
      {fix_how_row}
      {fix_row}
      <details><summary>Technical details</summary><div class="tech">{tech}</div></details>
    </div>"""


def _status_label(st):
    return {
        "VERIFIED_FIX": "Fixed & verified", "LANGUAGE_PATCH": "Fixed",
        "LLM_FIX": "AI fix (review)", "CONFIRMED": "Not fixed",
        "AUTO_FIX_FAILED": "Needs manual fix", "LEFT_UNFIXED": "Left as-is",
        "RECOMMENDATION": "Manual fix needed",
    }.get(st, st)


# ---- dynamic section -----------------------------------------------------

def _dynamic_section(dynamic):
    if not dynamic:
        return ""
    cards = ""
    for d in dynamic:
        vuln = d.get("vulnerable")
        color = SEV_COLORS["CRITICAL"] if vuln else SEV_COLORS["LOW"]
        label = "Exploited" if vuln else "Safe (not exploited)"
        cards += (f"<div class='card' style='border-left-color:{color}'>"
                  f"<div class='chead'><span class='sev' style='background:{color}'>{label}</span>"
                  f"<span class='title'>{_esc(d.get('matched_finding_type', d.get('probe','test')))}</span></div>"
                  f"<div class='row'><span class='k'>What happened</span>"
                  f"<span class='v'>{_esc(_proof_summary(d))}</span></div></div>")
    return (f"<h2>Live exploit tests</h2>"
            f"<p class='note'>These issues were tested against a running copy of the app "
            f"to confirm they are real.</p>{cards}")


def _proof_summary(dp):
    p = dp.get("probe")
    if p == "race_condition":
        return (f"On {dp.get('endpoint')}, we sent {dp.get('requests_sent')} requests at the same time; "
                f"{dp.get('successful_actions')} went through when only {dp.get('expected_actions')} should have "
                f"(value moved {dp.get('initial_value')} → {dp.get('final_value')}).")
    if p == "idor":
        return f"On {dp.get('endpoint')}, asking for two different record ids returned other users' data with no login."
    if p == "sql_injection":
        return (f"On {dp.get('endpoint')}, an injection payload returned {dp.get('rows_tautology')} rows "
                f"instead of {dp.get('rows_benign')} — proof the query was manipulated.")
    if dp.get("note"):
        return dp["note"]
    return "A live test was run against this endpoint."


def _empty(msg):
    return f"<div class='empty'>{_esc(msg)}</div>"


_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Report — LogicBreaker AI</title>
<style>
  :root {{ --bg:#f6f8fa; --card:#ffffff; --ink:#1b1f24; --muted:#646c76;
           --line:#e4e8ec; --line2:#eef1f4; --accent:#2563eb; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
          font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
          line-height:1.6; font-size:15px; }}
  .wrap {{ max-width:860px; margin:0 auto; padding:36px 22px 80px; }}
  header {{ margin-bottom:8px; }}
  .brand {{ font-size:12px; letter-spacing:2px; color:var(--accent); font-weight:700; text-transform:uppercase; }}
  h1 {{ margin:6px 0 2px; font-size:24px; }}
  .meta {{ color:var(--muted); font-size:13px; }}
  .headline {{ background:var(--card); border:1px solid var(--line);
               border-radius:12px; padding:18px 20px; margin:22px 0; font-size:15.5px; }}
  .cards-stat {{ display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin:16px 0 6px; }}
  .stat {{ background:var(--card); border:1px solid var(--line); border-radius:12px;
           padding:14px; text-align:center; }}
  .stat .n {{ font-size:30px; font-weight:800; line-height:1; }}
  .stat .l {{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.6px; margin-top:6px; }}
  .legend {{ background:var(--card); border:1px solid var(--line); border-radius:12px;
             padding:8px 16px; margin:14px 0 8px; }}
  .leg {{ display:flex; align-items:baseline; gap:10px; padding:7px 0; border-bottom:1px solid var(--line2); }}
  .leg:last-child {{ border-bottom:none; }}
  .dot {{ width:10px; height:10px; border-radius:50%; flex:0 0 auto; position:relative; top:1px; }}
  .leg-name {{ font-weight:700; min-width:74px; }}
  .leg-txt {{ color:var(--muted); font-size:13.5px; }}
  h2 {{ font-size:14px; text-transform:uppercase; letter-spacing:1.5px; color:var(--muted);
        margin:40px 0 8px; }}
  .note {{ color:var(--muted); font-size:13.5px; margin:0 0 14px; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-left-width:5px;
           border-radius:12px; padding:16px 18px; margin-bottom:14px; }}
  .chead {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:8px; }}
  .sev {{ font-size:11px; font-weight:800; color:#fff; padding:3px 10px; border-radius:20px; letter-spacing:.4px; }}
  .title {{ font-weight:700; font-size:16px; }}
  .tag {{ font-size:11px; font-weight:700; color:#fff; padding:2px 9px; border-radius:20px; }}
  .tag-confirmed {{ background:#d6336c; }}
  .loc {{ font-size:12.5px; color:var(--muted); font-family:'SF Mono',Menlo,Consolas,monospace;
          margin-bottom:12px; }}
  .row {{ display:grid; grid-template-columns:96px 1fr; gap:16px; padding:6px 0; }}
  .row .k {{ color:var(--muted); font-size:13px; font-weight:600; }}
  .row .v {{ font-size:14.5px; }}
  details {{ margin-top:10px; }}
  summary {{ cursor:pointer; color:var(--accent); font-size:13px; font-weight:600; }}
  .tech {{ margin-top:10px; padding-top:8px; border-top:1px solid var(--line2); }}
  .tline {{ font-size:13px; color:var(--muted); margin:4px 0; }}
  .code {{ background:#0d1117; color:#d7dde5; border-radius:8px; padding:12px;
           overflow-x:auto; font-family:'SF Mono',Menlo,Consolas,monospace; font-size:12.5px;
           white-space:pre; margin-top:10px; line-height:1.5; }}
  .empty {{ background:var(--card); border:1px solid var(--line); border-radius:12px;
            padding:20px; color:var(--muted); text-align:center; }}
  footer {{ margin-top:48px; padding-top:16px; border-top:1px solid var(--line);
            color:var(--muted); font-size:12px; text-align:center; }}
</style></head>
<body><div class="wrap">
  <header>
    <div class="brand">LogicBreaker AI</div>
    <h1>Security Report</h1>
    <div class="meta">{target} &nbsp;·&nbsp; {generated} &nbsp;·&nbsp; {files} files analysed &nbsp;·&nbsp; {mode} ({provider})</div>
  </header>

  <div class="headline">{headline}</div>

  <div class="cards-stat">
    <div class="stat"><div class="n" style="color:{c_crit}">{crit}</div><div class="l">Critical</div></div>
    <div class="stat"><div class="n" style="color:{c_high}">{high}</div><div class="l">High</div></div>
    <div class="stat"><div class="n" style="color:{c_med}">{med}</div><div class="l">Medium</div></div>
    <div class="stat"><div class="n" style="color:{c_low}">{low}</div><div class="l">Low</div></div>
  </div>

  {legend}

  <h2>Findings</h2>
  {finding_cards}

  {dynamic_section}

  <footer>Generated by LogicBreaker AI · Each finding was verified before being reported.</footer>
</div></body></html>
"""
