"""
CLI UI
======

Thin wrapper around `rich` for consistent, readable terminal output.

The original prototype crashed on Windows with a UnicodeEncodeError because
the default console codepage (cp1252) can't encode the emoji used in the
banner. ``main.py`` reconfigures stdout/stderr to UTF-8 with
``errors="replace"`` before this module is imported, and every print here
goes through a single ``Console`` instance so that fix only has to live in
one place.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

# Colors matching the requested reference design (cream/yellow letters,
# warm golden-orange border)
BANNER_TEXT_COLOR = "#F5E6A8"
BANNER_BORDER_COLOR = "#D4A017"

BANNER = (
    "          ██╗      ██████╗  ██████╗ ██╗ ██████╗\n"
    "          ██║     ██╔═══██╗██╔════╝ ██║██╔════╝\n"
    "          ██║     ██║   ██║██║  ███╗██║██║     \n"
    "          ██║     ██║   ██║██║   ██║██║██║     \n"
    "          ███████╗╚██████╔╝╚██████╔╝██║╚██████╗\n"
    "          ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝ ╚═════╝\n"
    "                                                \n"
    "██████╗ ██████╗ ███████╗ █████╗ ██╗  ██╗███████╗██████╗ \n"
    "██╔══██╗██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██╔════╝██╔══██╗\n"
    "██████╔╝██████╔╝█████╗  ███████║█████╔╝ █████╗  ██████╔╝\n"
    "██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗\n"
    "██████╔╝██║  ██║███████╗██║  ██║██║  ██╗███████╗██║  ██║\n"
    "╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝"
)


def banner():
    console.print(Panel(
        Text(BANNER, style=f"bold {BANNER_TEXT_COLOR}"),
        title=f"[bold {BANNER_TEXT_COLOR}]LogicBreaker[/]",
        subtitle=f"[{BANNER_TEXT_COLOR}]AI-Powered Business-logic vulnerability hunter & patcher[/]",
        border_style=BANNER_BORDER_COLOR,
        padding=(1, 2),
    ))


def section(title: str):
    console.print()
    console.rule(f"[bold cyan]{title}")


def info(msg: str):
    console.print(f"[bold blue][*][/bold blue] {msg}")


def success(msg: str):
    console.print(f"[bold green][+][/bold green] {msg}")


def warning(msg: str):
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def error(msg: str):
    console.print(f"[bold red][x][/bold red] {msg}")


def architect_summary(data: dict):
    table = Table(title="Codebase Map", show_header=True, header_style="bold cyan")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Files scanned", str(data.get("files", 0)))
    table.add_row("Functions/methods extracted", str(data.get("functions", 0)))
    table.add_row("HTTP routes detected", str(data.get("routes", 0)))
    table.add_row("Languages detected", str(data.get("languages", 0)))
    console.print(table)


SEV_STYLE = {"CRITICAL": "bold white on red", "HIGH": "bold red",
             "MEDIUM": "yellow", "LOW": "cyan"}


def findings_table(findings: list):
    if not findings:
        console.print("[green]No vulnerability candidates found.[/green]")
        return

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings = sorted(findings, key=lambda f: order.get(f["severity"], 9))

    table = Table(title=f"Findings ({len(findings)})", show_header=True, header_style="bold cyan")
    table.add_column("Severity")
    table.add_column("Type")
    table.add_column("CWE")
    table.add_column("Language")
    table.add_column("Location")
    table.add_column("Conf", justify="right")
    table.add_column("Status")

    for f in findings:
        status = f["status"]
        status_disp = f"[bold red]{status}[/]" if status == "CONFIRMED" else status
        table.add_row(
            f"[{SEV_STYLE.get(f['severity'], 'white')}]{f['severity']}[/]",
            f["type"],
            f["cwe"],
            f["language"],
            f"{f['file']}:{f['lineno']}",
            f"{int(f['confidence']*100)}%",
            status_disp,
        )
    console.print(table)


def dynamic_result(dyn: dict):
    probe = dyn.get("probe", "probe")
    endpoint = dyn.get("endpoint", "")
    vuln = dyn.get("vulnerable")

    if probe == "race_condition":
        title = f"Live Exploit — Race Condition  ({endpoint})"
        rows = [
            ("Concurrent requests sent", str(dyn.get("requests_sent", "?"))),
            ("Initial value", str(dyn.get("initial_value"))),
            ("Successful actions (actual)", str(dyn.get("successful_actions"))),
            ("Successful actions (expected)", str(dyn.get("expected_actions"))),
            ("Final value", str(dyn.get("final_value"))),
        ]
    elif probe == "idor":
        title = f"Live Exploit — IDOR  ({endpoint})"
        rows = [("Sequential ids returned distinct objects", "yes" if vuln else "no")]
    elif probe == "sql_injection":
        title = f"Live Exploit — SQL Injection  ({endpoint})"
        rows = [
            ("Rows (benign value)", str(dyn.get("rows_benign"))),
            ("Rows (tautology payload)", str(dyn.get("rows_tautology"))),
            ("DB error signature", "yes" if dyn.get("error_signature") else "no"),
        ]
    else:
        title = f"Live Exploit — {probe}"
        rows = [("vulnerable", str(vuln))]

    table = Table(title=title, show_header=True, header_style="bold cyan")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    for k, v in rows:
        table.add_row(k, v)
    console.print(table)

    if vuln:
        error(f"CONFIRMED EXPLOITABLE — {probe} reproduced live on {endpoint}.")
    else:
        success(f"Not exploitable on {endpoint}.")


def heal_result(finding: dict, result: dict):
    status = result["status"]
    fn = finding.get("function", finding.get("file", ""))
    if status == "VERIFIED_FIX":
        success(f"{fn}: patch generated AND re-verified by re-running the attack.")
        v = result.get("verification", {})
        console.print(f"    re-attack -> successes={v.get('successful_actions')}, "
                      f"final={v.get('final_value')}, vulnerable={v.get('vulnerable')}")
    elif status == "LANGUAGE_PATCH":
        info(f"{fn}: deterministic language patch produced (review & test before merge).")
    elif status == "AUTO_FIX_FAILED":
        warning(f"{fn}: auto-fix did not pass re-verification. Rolled back — manual review required.")
    elif status == "LLM_FIX":
        info(f"{fn}: LLM-suggested fix generated (unverified — review before applying).")
    else:
        info(f"{fn}: recommendation included in report.")


def final_summary(output_dir: str, report_path: str, patch_count: int):
    section("Done")
    table = Table(show_header=False, box=None)
    table.add_row("Report", report_path)
    table.add_row("Patches written", str(patch_count))
    table.add_row("Output directory", output_dir)
    console.print(table)