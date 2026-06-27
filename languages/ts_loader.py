"""
Tree-sitter language loader (modern API)
=======================================

Loads tree-sitter grammars from the individual ``tree-sitter-<lang>`` PyPI
packages using the current ``Language(<pkg>.language())`` API. This is the
maintained path that works on Python 3.12, 3.13, and 3.14+ (unlike the older
all-in-one ``tree-sitter-languages`` wheel, which is pinned to <=3.11).

Each language is loaded lazily and cached. A grammar that isn't installed is
simply skipped -- the file then falls back to generic handling, so a missing
optional grammar never crashes a scan.
"""

import importlib
import warnings

warnings.filterwarnings("ignore")

try:
    from tree_sitter import Language, Parser
    _TS_OK = True
except Exception:  # pragma: no cover
    _TS_OK = False

# language name -> (pip module, language-function name)
_LANG_SPECS = {
    "python":     ("tree_sitter_python", "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "tsx":        ("tree_sitter_typescript", "language_tsx"),
    "java":       ("tree_sitter_java", "language"),
    "go":         ("tree_sitter_go", "language"),
    "php":        ("tree_sitter_php", "language_php"),
    "ruby":       ("tree_sitter_ruby", "language"),
    "c_sharp":    ("tree_sitter_c_sharp", "language"),
    "c":          ("tree_sitter_c", "language"),
    "cpp":        ("tree_sitter_cpp", "language"),
    "rust":       ("tree_sitter_rust", "language"),
    "kotlin":     ("tree_sitter_kotlin", "language"),
    "scala":      ("tree_sitter_scala", "language"),
    "bash":       ("tree_sitter_bash", "language"),
    "lua":        ("tree_sitter_lua", "language"),
    "json":       ("tree_sitter_json", "language"),
    "yaml":       ("tree_sitter_yaml", "language"),
    "html":       ("tree_sitter_html", "language"),
    "css":        ("tree_sitter_css", "language"),
    "sql":        ("tree_sitter_sql", "language"),
}

_PARSER_CACHE = {}
_LANG_CACHE = {}


def available() -> bool:
    return _TS_OK


def _load_language(name):
    if name in _LANG_CACHE:
        return _LANG_CACHE[name]
    spec = _LANG_SPECS.get(name)
    if not spec or not _TS_OK:
        _LANG_CACHE[name] = None
        return None
    module_name, func_name = spec
    try:
        mod = importlib.import_module(module_name)
        lang_fn = getattr(mod, func_name)
        lang = Language(lang_fn())
    except Exception:
        lang = None
    _LANG_CACHE[name] = lang
    return lang


def get_parser(name):
    """Return a cached Parser for the language, or None if unavailable."""
    if name in _PARSER_CACHE:
        return _PARSER_CACHE[name]
    lang = _load_language(name)
    if lang is None:
        _PARSER_CACHE[name] = None
        return None
    try:
        parser = Parser(lang)
    except Exception:
        try:
            parser = Parser()
            parser.language = lang
        except Exception:
            parser = None
    _PARSER_CACHE[name] = parser
    return parser


def installed_languages():
    """Languages whose grammar packages are actually importable right now."""
    out = []
    for name in _LANG_SPECS:
        if get_parser(name) is not None:
            out.append(name)
    return sorted(out)
