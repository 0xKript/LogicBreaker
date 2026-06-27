"""
Interactive startup flow
=======================

Implements the requested launch experience:

  1. Ask the user whether to run a fast scan (no API, fully heuristic) or an
     API-assisted scan.
  2. If API-assisted, show a numbered menu of the top providers.
  3. Prompt for the chosen provider's API key in a warm, readable colour
     (cream/gold -- not red), with the key hidden as it is typed.
  4. Ask for the target path to scan.

All prompts use `rich` so they are consistent with the rest of the UI and
work cross-platform. Nothing here is required for non-interactive/CI use --
``main.py`` also accepts flags.
"""

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.text import Text

console = Console()

PROMPT_COLOR = "#F5E6A8"   # cream/gold, easy on the eyes (not red)
ACCENT = "#D4A017"


def choose_mode():
    """Offer 4 scan modes:
      1  Fast       — rule engine only (fast, free, offline)
      2  AI + API   — AI deep analysis via API (slowest, most thorough)
      3  Hybrid     — rule engine + AI merged (best coverage)
      4  Dynamic    — launches the app + fires real exploits (live proof)
    """
    console.print()
    panel = Panel(
        Text.from_markup(
            "[bold]How do you want to run the scan?[/bold]\n\n"
            f"  [{PROMPT_COLOR}]1[/]  Fast        [dim]— rule engine only (fast, free, offline)[/dim]\n"
            f"  [{PROMPT_COLOR}]2[/]  AI + API    [dim]— AI deep analysis via API (slowest, most thorough)[/dim]\n"
            f"  [{PROMPT_COLOR}]3[/]  Hybrid      [dim]— rule engine + AI merged (best coverage)[/dim]\n"
            f"  [{PROMPT_COLOR}]4[/]  Dynamic     [dim]— launches the app + fires real exploits (live proof)[/dim]"
        ),
        border_style=ACCENT, title=f"[{PROMPT_COLOR}]Scan mode[/]", padding=(1, 2),
    )
    console.print(panel)
    choice = Prompt.ask(f"[{PROMPT_COLOR}]Select[/]",
                        choices=["1", "2", "3", "4"], show_default=False)
    return {"1": "fast", "2": "ai", "3": "hybrid", "4": "dynamic"}[choice]


def choose_provider():
    from agents.llm_client import provider_menu
    menu = provider_menu()

    table = Table(show_header=True, header_style=f"bold {PROMPT_COLOR}", border_style=ACCENT)
    table.add_column("#", width=4, justify="right")
    table.add_column("Provider")
    for i, (key, label, hint) in enumerate(menu, 1):
        table.add_row(str(i), label)
    console.print()
    console.print(Panel(table, title=f"[{PROMPT_COLOR}]Choose an API provider[/]",
                        border_style=ACCENT, padding=(1, 2)))

    choices = [str(i) for i in range(1, len(menu) + 1)]
    idx = Prompt.ask(f"[{PROMPT_COLOR}]Select provider[/]", choices=choices, show_default=False)
    key, label, hint = menu[int(idx) - 1]
    return key, label, hint


def _mask_key(key):
    """Masked form of an API key for on-screen confirmation: ONLY the last 4
    characters are ever shown, never the full secret (e.g. '****CkIr')."""
    if not key:
        return ""
    return "****" + (key[-4:] if len(key) >= 4 else key)


def prompt_api_key(provider_key, label, hint):
    """Prompt for the API key, then VERIFY it live against the chosen provider.
    Re-prompts on empty input, malformed keys, or keys the provider rejects.
    The user must provide a key that actually works, or type 'back'.

    SECURITY: the key is read with HIDDEN input (never echoed) and is only ever
    confirmed back to the user in MASKED form (last 4 chars + length). It is used
    in-memory for this session only and is never printed, logged, or written."""
    console.print()
    console.print(Text.from_markup(
        f"[{PROMPT_COLOR}]🔑  Enter your {label.split('(')[0].strip()} API key[/]"
        f"  [dim]({hint})[/dim]"
    ))
    console.print(Text.from_markup(
        f"[dim]It is used only for this session and is never stored to disk. "
        f"Type 'back' to return to scan-mode selection.[/dim]"
    ))
    from agents.llm_client import LLMClient
    console.print(Text.from_markup(
        "[dim]Tip: paste your key and press Enter — input is hidden for security. "
        "Once entered, a masked form (last 4 chars + length) is shown so you can "
        "confirm it pasted fully.[/dim]"
    ))
    while True:
        try:
            # HIDDEN input (password=True): the key is never echoed to the screen
            # or terminal scrollback. We confirm a correct paste via the masked
            # echo + character count below, not by showing the secret.
            key = Prompt.ask(f"[{PROMPT_COLOR}]API key[/]", password=True).strip()
        except (KeyboardInterrupt, EOFError):
            console.print()
            console.print(Text.from_markup(f"[{PROMPT_COLOR}]Cancelled — returning to scan-mode "
                                           f"selection.[/]"))
            return None
        # tolerate accidental wrapping quotes/whitespace from copy-paste
        key = key.strip().strip('"').strip("'").strip()
        if key.lower() == "back":
            return None
        if not key:
            console.print(Text.from_markup(
                "[bold red]✗ Error:[/bold red] no API key entered. You chose API-assisted mode, "
                "so a key is required.\n"
                f"[dim]Paste a valid {label.split('(')[0].strip()} key, or type 'back' "
                f"to switch to fast scan.[/dim]"
            ))
            continue

        # masked confirmation so the user can verify a full paste WITHOUT the key
        # ever appearing on screen.
        console.print(Text.from_markup(
            f"[dim]Received key [/dim][{PROMPT_COLOR}]{_mask_key(key)}[/] "
            f"[dim]({len(key)} characters).[/dim]"
        ))
        # LIVE verification against the provider
        console.print(Text.from_markup(f"[dim]Verifying the key with {provider_key}…[/dim]"))
        client = LLMClient(provider=provider_key, api_key=key)
        ok, message = client.validate_key()
        if ok:
            console.print(Text.from_markup(f"[bold green]✓[/bold green] {message}"))
            return key
        # rejected -> explain why and re-prompt
        console.print(Text.from_markup(
            f"[bold red]✗ Invalid key:[/bold red] {message}\n"
            f"[dim]Enter a valid {label.split('(')[0].strip()} key, or type 'back' "
            f"to switch to fast scan.[/dim]"
        ))


def prompt_target():
    """Ask for the target path. An empty entry is an error -- we never default
    to scanning the tool's own directory."""
    console.print()
    while True:
        path = Prompt.ask(f"[{PROMPT_COLOR}]Path to the code you want to scan[/]").strip().strip('"')
        if not path:
            console.print(Text.from_markup(
                "[bold red]✗ Error:[/bold red] a target path is required. "
                "[dim]e.g. C:\\\\projects\\\\my-app[/dim]"
            ))
            continue
        import os
        if not os.path.isdir(path):
            console.print(Text.from_markup(
                f"[bold red]✗ Error:[/bold red] not a folder: [dim]{path}[/dim]"
            ))
            continue
        return path


def configure_interactively():
    """Run the full interactive flow and return a config dict.

    Supports 4 modes:
      fast    — rule engine only (no API key needed)
      ai      — AI only (needs API key, no rule engine)
      hybrid  — rule engine + AI merged (best for enterprise)
      dynamic — rule engine + AI + live exploitation (launches the app)
    """
    while True:
        mode = choose_mode()
        provider = api_key = None
        # modes 2 (ai), 3 (hybrid), 4 (dynamic) all need an API key
        if mode in ("ai", "hybrid", "dynamic"):
            provider, label, hint = choose_provider()
            api_key = prompt_api_key(provider, label, hint)
            if api_key is None:
                # user chose to go back -> restart mode selection
                console.print(Text.from_markup(f"[{PROMPT_COLOR}]Returning to scan-mode selection…[/]"))
                continue
        target = prompt_target()
        return {"mode": mode, "provider": provider, "api_key": api_key,
                "target": target}
