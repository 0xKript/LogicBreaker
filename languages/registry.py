"""
Language Registry
=================

Maps file extensions to languages and languages to tree-sitter grammars.

This is the foundation of LogicBreaker AI's multi-language support. Parsing
is backed by ``tree-sitter`` grammars (via ``tree-sitter-languages``), which
provides real concrete syntax trees for 40+ languages -- not regex guesses.

Two tiers of support are distinguished honestly:

  * DEEP   -- the language has a dedicated structural extractor in
              ``languages/`` that pulls out functions, parameters, routes,
              and the data-flow signals the matchers rely on. Findings here
              are high-confidence and (for web frameworks) dynamically
              exploitable.
  * PARSED -- the language has a working tree-sitter grammar, so the tool can
              build a syntax tree, extract function/method boundaries
              generically, and run the language-agnostic structural matchers
              + (optionally) LLM triage. It just doesn't yet have a
              hand-tuned extractor. This is real, useful coverage -- it is
              clearly labelled as "generic" in the report so nobody mistakes
              it for the deep path.

This separation is deliberate: it lets the tool genuinely accept 40+
languages today, while being transparent about depth of analysis per
language.
"""

# extension -> canonical language name (tree-sitter grammar key)
EXTENSION_MAP = {
    # Python
    ".py": "python", ".pyw": "python", ".pyi": "python",
    # JavaScript / TypeScript
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "tsx", ".mts": "typescript", ".cts": "typescript",
    # JVM
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".scala": "scala", ".sc": "scala",
    ".groovy": "java",  # closest grammar
    # C family
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp",
    ".cs": "c_sharp",
    ".m": "objc", ".mm": "objc",
    # Go / Rust
    ".go": "go",
    ".rs": "rust",
    # PHP
    ".php": "php", ".php3": "php", ".php4": "php", ".php5": "php", ".phtml": "php",
    # Ruby
    ".rb": "ruby", ".rake": "ruby", ".gemspec": "ruby",
    # Functional
    ".ex": "elixir", ".exs": "elixir",
    ".erl": "erlang", ".hrl": "erlang",
    ".hs": "haskell", ".lhs": "haskell",
    ".ml": "ocaml", ".mli": "ocaml",
    ".elm": "elm",
    ".clj": "commonlisp", ".cljs": "commonlisp", ".cljc": "commonlisp",
    ".lisp": "commonlisp", ".lsp": "commonlisp", ".el": "elisp",
    ".jl": "julia",
    # Scripting / shell
    ".sh": "bash", ".bash": "bash", ".zsh": "bash",
    ".pl": "perl", ".pm": "perl",
    ".lua": "lua",
    ".r": "r", ".R": "r",
    # Data / config / markup
    ".sql": "sql", ".ddl": "sql", ".dml": "sql",
    ".html": "html", ".htm": "html",
    ".css": "css", ".scss": "css", ".sass": "css",
    ".json": "json", ".json5": "json",
    ".yaml": "yaml", ".yml": "yaml",
    ".toml": "toml",
    ".xml": "html",
    ".md": "markdown", ".markdown": "markdown",
    ".dockerfile": "dockerfile",
    ".tf": "hcl", ".hcl": "hcl",
    ".mk": "make",
    ".f": "fortran", ".f90": "fortran", ".f95": "fortran",
}

# special filenames (no extension or non-standard) -> language
FILENAME_MAP = {
    "Dockerfile": "dockerfile",
    "Makefile": "make",
    "makefile": "make",
    "Gemfile": "ruby",
    "Rakefile": "ruby",
    "CMakeLists.txt": "make",
    "go.mod": "gomod",
    "requirements.txt": "text",
    ".env": "text",
}

# Languages that currently have a deep, hand-tuned extractor.
DEEP_LANGUAGES = {"python", "javascript", "typescript", "tsx", "java",
                  "go", "php", "c_sharp", "ruby"}

# Human-friendly display names
DISPLAY_NAMES = {
    "python": "Python", "javascript": "JavaScript", "typescript": "TypeScript",
    "tsx": "TypeScript (TSX)", "java": "Java", "kotlin": "Kotlin",
    "scala": "Scala", "c": "C", "cpp": "C++", "c_sharp": "C#", "objc": "Objective-C",
    "go": "Go", "rust": "Rust", "php": "PHP", "ruby": "Ruby", "elixir": "Elixir",
    "erlang": "Erlang", "haskell": "Haskell", "ocaml": "OCaml", "elm": "Elm",
    "commonlisp": "Lisp", "elisp": "Emacs Lisp", "julia": "Julia", "bash": "Shell",
    "perl": "Perl", "lua": "Lua", "r": "R", "sql": "SQL", "html": "HTML",
    "css": "CSS", "json": "JSON", "yaml": "YAML", "toml": "TOML",
    "markdown": "Markdown", "dockerfile": "Dockerfile", "hcl": "HCL/Terraform",
    "make": "Make", "fortran": "Fortran", "gomod": "Go Modules",
}


def detect_language(path: str):
    """Return the canonical language name for a file path, or None."""
    import os
    base = os.path.basename(path)
    if base in FILENAME_MAP:
        return FILENAME_MAP[base]
    _, ext = os.path.splitext(base)
    return EXTENSION_MAP.get(ext.lower())


def is_deep(language: str) -> bool:
    return language in DEEP_LANGUAGES


def display_name(language: str) -> str:
    return DISPLAY_NAMES.get(language, language)


def supported_extensions():
    return sorted(EXTENSION_MAP.keys())


def supported_languages():
    langs = set(EXTENSION_MAP.values()) | set(FILENAME_MAP.values())
    langs.discard("text")
    return sorted(langs)
