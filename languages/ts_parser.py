"""
Universal tree-sitter parser
============================

Provides:

  * ``parse_source(language, bytes)`` -> a parsed tree
  * ``extract_functions(...)`` -> a list of language-agnostic "code units"
    (functions/methods) with their exact source text, name, parameter list,
    and byte/line span.

Grammars are loaded via ``languages.ts_loader``, which uses the maintained,
per-language ``tree-sitter-<lang>`` packages and the modern tree-sitter API.
This works on current Python versions (3.12 / 3.13 / 3.14+).

The function-node type names differ per grammar, so a per-language table maps
each grammar to the node types that represent "a callable unit" and how to
find its name/parameters. Anything not in the table still parses; it just
won't yield function-level units (the file is then analysed as a whole by the
generic matchers).
"""

import warnings

warnings.filterwarnings("ignore")

from languages.ts_loader import get_parser, available as _ts_available

_TS_AVAILABLE = _ts_available()


# grammar -> {function node types}, plus the field/child used for the name.
FUNCTION_NODE_TYPES = {
    "python": {"function_definition"},
    "javascript": {"function_declaration", "method_definition",
                   "arrow_function", "function_expression", "function",
                   "generator_function", "generator_function_declaration"},
    "typescript": {"function_declaration", "method_definition",
                   "arrow_function", "function_expression", "function",
                   "generator_function", "generator_function_declaration"},
    "tsx": {"function_declaration", "method_definition",
            "arrow_function", "function_expression", "function"},
    "java": {"method_declaration", "constructor_declaration"},
    "kotlin": {"function_declaration"},
    "scala": {"function_definition"},
    "c": {"function_definition"},
    "cpp": {"function_definition"},
    "c_sharp": {"method_declaration", "constructor_declaration",
                "local_function_statement"},
    "objc": {"method_definition"},
    "go": {"function_declaration", "method_declaration"},
    "rust": {"function_item"},
    "php": {"function_definition", "method_declaration"},
    "ruby": {"method", "singleton_method"},
    "elixir": {"call"},  # def/defp are calls in elixir grammar
    "lua": {"function_declaration", "function_definition"},
    "perl": {"subroutine_declaration_statement"},
    "r": {"function_definition"},
    "julia": {"function_definition", "short_function_definition"},
    "haskell": {"function", "signature"},
}


def available() -> bool:
    return _TS_AVAILABLE


def parse_source(language: str, source_bytes: bytes):
    parser = get_parser(language)
    if parser is None:
        return None
    return parser.parse(source_bytes)


def _node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _find_name(node, source_bytes: bytes):
    """Best-effort extraction of a callable's name across grammars."""
    # most grammars expose a 'name' field
    name_node = node.child_by_field_name("name")
    if name_node is not None:
        return _node_text(name_node, source_bytes)
    # fallback: first identifier-ish child
    for child in node.children:
        if "identifier" in child.type or child.type == "name":
            return _node_text(child, source_bytes)
    return "<anonymous>"


def _find_params(node, source_bytes: bytes):
    """Return a list of parameter names (best effort, grammar-agnostic)."""
    params = []
    param_node = (node.child_by_field_name("parameters")
                  or node.child_by_field_name("parameter_list"))
    if param_node is None:
        for child in node.children:
            if "parameter" in child.type and child.type.endswith(("list", "s")):
                param_node = child
                break
    if param_node is None:
        return params

    for child in param_node.children:
        if child.type in (",", "(", ")", "[", "]"):
            continue
        ident = None
        if "identifier" in child.type:
            ident = _node_text(child, source_bytes)
        else:
            name_field = child.child_by_field_name("name")
            if name_field is not None:
                ident = _node_text(name_field, source_bytes)
            else:
                for sub in child.children:
                    if "identifier" in sub.type or sub.type == "variable_name":
                        ident = _node_text(sub, source_bytes)
                        break
        if ident:
            params.append(ident.lstrip("$&@%"))
    return params


def _synth_anon_name(node, source_bytes: bytes):
    """Give anonymous functions a meaningful name from their surrounding
    context (the route path they handle, or the variable they're assigned to)."""
    import re
    parent = node.parent
    # climb up a few levels looking for a route string or an assignment target
    hops = 0
    cur = parent
    while cur is not None and hops < 4:
        text = source_bytes[cur.start_byte:min(cur.end_byte, cur.start_byte + 200)].decode("utf-8", errors="replace")
        # route path?
        rm = re.search(r'\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', text, re.I)
        if rm:
            return f"handler[{rm.group(1).upper()} {rm.group(2)}]"
        # assignment: const x = () => ...
        am = re.search(r'(?:const|let|var)\s+(\w+)\s*=', text)
        if am:
            return am.group(1)
        cur = cur.parent
        hops += 1
    return f"anonymous@L{node.start_point[0] + 1}"


def _decorators_text(node, source_bytes: bytes) -> str:
    """Decorator lines attached to this function/method. Tree-sitter puts
    decorators in the PARENT `decorated_definition`, so the function node's own
    text excludes them -- which made @login_required / @limiter.limit invisible
    to matchers. Capture them here as a separate field."""
    parent = getattr(node, "parent", None)
    if parent is not None and parent.type in ("decorated_definition",):
        parts = [_node_text(c, source_bytes) for c in parent.children
                 if c.type == "decorator"]
        return "\n".join(parts)
    return ""


def extract_functions(language: str, source_bytes: bytes, rel_path: str):
    """Return a list of code-unit dicts for the given file."""
    if not _TS_AVAILABLE:
        return []
    node_types = FUNCTION_NODE_TYPES.get(language)
    if not node_types:
        return []

    tree = parse_source(language, source_bytes)
    if tree is None:
        return []
    units = []

    def walk(node, class_name=None):
        # track enclosing class/struct for qualname
        new_class = class_name
        if node.type in ("class_definition", "class_declaration",
                          "class_specifier", "struct_specifier", "module"):
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                new_class = _node_text(name_node, source_bytes)

        if node.type in node_types:
            name = _find_name(node, source_bytes)
            # elixir: only treat def/defp calls as functions
            if language == "elixir":
                if name not in ("def", "defp"):
                    for child in node.children:
                        pass
            # synthesize a name for anonymous functions/arrows from context
            if name == "<anonymous>":
                name = _synth_anon_name(node, source_bytes)
            qualname = f"{new_class}.{name}" if new_class else name
            units.append({
                "name": name,
                "qualname": qualname,
                "class_name": new_class,
                "file": rel_path,
                "language": language,
                "lineno": node.start_point[0] + 1,
                "end_lineno": node.end_point[0] + 1,
                "start_byte": node.start_byte,
                "end_byte": node.end_byte,
                "source": _node_text(node, source_bytes),
                "decorators": _decorators_text(node, source_bytes),
                "params": _find_params(node, source_bytes),
                "node": node,
            })

        for child in node.children:
            walk(child, new_class)

    walk(tree.root_node)
    return units
