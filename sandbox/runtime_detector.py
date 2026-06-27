"""
Runtime detector
================

Discovers which language runtimes are actually installed on the host, so the
live-exploitation engine can launch a target in ANY language whose runtime is
present -- five languages or a hundred, whatever the machine has.

This is the honest core of "multi-language live exploitation": we cannot ship
a compiler/interpreter for every language (those are huge programs built by
their own communities), but we CAN detect and drive whatever is installed.

For each language we record:
  * the command(s) that prove it is installed
  * how to launch a web app written in it
  * whether it needs a build step first
"""

import shutil
import subprocess


# command probes per language: the first command found on PATH wins
RUNTIME_PROBES = {
    "python":      ["python3", "python"],
    "javascript":  ["node"],
    "typescript":  ["ts-node", "node"],      # ts via ts-node, or compiled to JS
    "php":         ["php"],
    "ruby":        ["ruby"],
    "go":          ["go"],
    "java":        ["java"],                  # running needs javac too for source
    "c_sharp":     ["dotnet"],
    "rust":        ["cargo", "rustc"],
    "kotlin":      ["kotlin", "kotlinc"],
    "scala":       ["scala"],
    "perl":        ["perl"],
    "lua":         ["lua"],
    "bash":        ["bash"],
    "r":           ["Rscript"],
    "elixir":      ["elixir"],
    "dart":        ["dart"],
    "swift":       ["swift"],
    "groovy":      ["groovy"],
    "clojure":     ["clojure"],
    "deno":        ["deno"],
}

# languages that need a compile/build step before they can run a web server
NEEDS_BUILD = {"go", "java", "c_sharp", "rust", "kotlin", "scala", "swift"}

# version flag per command (best-effort, for reporting)
VERSION_FLAG = {
    "go": "version",       # `go version` (no dashes)
    "dotnet": "--version",
}


def _which(cmd):
    return shutil.which(cmd)


def _version_of(cmd):
    flag = VERSION_FLAG.get(cmd, "--version")
    try:
        out = subprocess.run([cmd, flag], capture_output=True, text=True, timeout=6)
        line = (out.stdout or out.stderr).strip().splitlines()
        return line[0][:80] if line else ""
    except Exception:
        return ""


def detect_runtimes():
    """Return {language: {'command': str, 'path': str, 'version': str,
    'needs_build': bool}} for every language whose runtime is installed."""
    found = {}
    for lang, probes in RUNTIME_PROBES.items():
        for cmd in probes:
            path = _which(cmd)
            if path:
                found[lang] = {
                    "command": cmd,
                    "path": path,
                    "version": _version_of(cmd),
                    "needs_build": lang in NEEDS_BUILD,
                }
                break
    return found


def is_available(language):
    """Quick check: is there a runtime for this language?"""
    for cmd in RUNTIME_PROBES.get(language, []):
        if _which(cmd):
            return True
    return False


def command_for(language):
    """Return the runnable command for a language, or None."""
    for cmd in RUNTIME_PROBES.get(language, []):
        if _which(cmd):
            return cmd
    return None


def summary_lines():
    """Human-readable list of detected runtimes (for --list-runtimes)."""
    found = detect_runtimes()
    lines = []
    for lang in sorted(RUNTIME_PROBES):
        if lang in found:
            info = found[lang]
            v = f"  ({info['version']})" if info["version"] else ""
            build = "  [needs build]" if info["needs_build"] else ""
            lines.append(f"  ● {lang:12} via {info['command']}{v}{build}")
        else:
            lines.append(f"  ○ {lang:12} not installed")
    return lines, len(found)


if __name__ == "__main__":
    lines, n = summary_lines()
    print(f"Detected {n} language runtime(s):\n")
    print("\n".join(lines))
