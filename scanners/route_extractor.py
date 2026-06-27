"""
Route extractor (multi-framework)
================================

Extracts HTTP routes from source across common web frameworks so the dynamic
exploitation stage can target *any* endpoint, not a hardcoded pair. Detection
is regex-based over the function/file source (resilient across framework
versions) and records the method, path, and the handler unit it belongs to.

 added WordPress plugin hook support -- WP plugins register handlers via
add_action('wp_ajax_my_action', 'handler') and add_menu_page() / add_submenu_page().
These are now recognised so the dynamic stage can target them. This was a major
gap for WordPress-plugin scanning: a plugin's vulnerable code lives in a hook
callback, and without route extraction the dynamic tester could not reach it.

Supported shapes (best-effort):
  * Flask / FastAPI:  @app.route("/x"), @app.get("/x"), @router.post("/x")
  * Django:           path("x/", view), re_path(r"^x$", view)
  * Express / Koa:    app.get("/x", ...), router.post("/x", ...)
  * Spring (Java):    @GetMapping("/x"), @RequestMapping(...)
  * Go (net/http,
    gin, echo, chi):  r.GET("/x", ...), mux.HandleFunc("/x", ...)
  * PHP (Laravel,
    Slim):            Route::get('/x', ...), $app->post('/x', ...)
  * Ruby on Rails:    get '/x', to: ...
  * WordPress:        add_action('wp_ajax_X', '...'), add_menu_page(...),
                      register_rest_route('namespace', '/path', ...)
"""

import re

ROUTE_PATTERNS = [
    # decorator style (python): @app.route("/x", methods=["POST"]) / @app.get("/x")
    (re.compile(r'@\w+\.(route|get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'
                r'(?:[^)]*methods\s*=\s*\[([^\]]*)\])?', re.I), "decorator"),
    # express/koa/gin/echo: app.get("/x", ...) , r.POST("/x", ...)
    (re.compile(r'\b\w+\.(get|post|put|delete|patch|all)\s*\(\s*["\']([^"\']+)["\']', re.I), "call"),
    # spring: @GetMapping("/x") @PostMapping(value="/x")
    (re.compile(r'@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']', re.I), "spring"),
    # django: path("x/", view) re_path(r"^x$", view)
    (re.compile(r'\b(path|re_path|url)\s*\(\s*r?["\']([^"\']+)["\']', re.I), "django"),
    # go mux: HandleFunc("/x", ...)
    (re.compile(r'\bHandleFunc\s*\(\s*["\']([^"\']+)["\']', re.I), "go_mux"),
    # php laravel/slim: Route::get('/x', ...) $app->post('/x', ...)
    (re.compile(r'(?:Route::|->)(get|post|put|delete|patch|any)\s*\(\s*["\']([^"\']+)["\']', re.I), "php"),
    # rails: get '/x', to: '...'
    (re.compile(r'^\s*(get|post|put|delete|patch)\s+["\']([^"\']+)["\']', re.I | re.M), "rails"),
    # ruby webrick: server.mount_proc '/x' do ...
    (re.compile(r'\bmount_proc\s*\(?\s*["\']([^"\']+)["\']', re.I), "webrick"),
    # WordPress: register_rest_route('namespace', '/path', ...) -> /wp-json/namespace/path
    (re.compile(r"\bregister_rest_route\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]", re.I), "wp_rest"),
    # WordPress: add_action('wp_ajax_X', 'handler') -> /wp-admin/admin-ajax.php?action=X
    (re.compile(r"\badd_action\s*\(\s*['\"]wp_ajax_([^'\"]+)['\"]", re.I), "wp_ajax"),
    # WordPress: add_action('wp_ajax_nopriv_X', 'handler') -> public ajax
    (re.compile(r"\badd_action\s*\(\s*['\"]wp_ajax_nopriv_([^'\"]+)['\"]", re.I), "wp_ajax_nopriv"),
    # WordPress: add_menu_page('Title', 'Menu', 'cap', 'slug', 'handler')
    # we capture the slug as the path -> /wp-admin/admin.php?page=slug
    (re.compile(r"\badd_menu_page\s*\([^)]*['\"]([^'\"]+)['\"]\s*,\s*['\"]?([^,'\")]+)", re.I), "wp_menu"),
    # WordPress: add_submenu_page(parent, 'Title', 'Menu', 'cap', 'slug', 'handler')
    (re.compile(r"\badd_submenu_page\s*\([^)]*['\"]([^'\"]+)['\"]\s*,\s*['\"]?([^,'\")]+)", re.I), "wp_submenu"),
]

METHOD_FROM_VERB = {
    "get": ["GET"], "post": ["POST"], "put": ["PUT"], "delete": ["DELETE"],
    "patch": ["PATCH"], "all": ["GET", "POST"], "any": ["GET", "POST"],
    "route": ["GET"], "request": ["GET", "POST"],
}


def extract_routes_from_unit(unit):
    """Return [{path, methods}] discovered inside a single function unit."""
    src = unit["source"]
    routes = []
    for pattern, kind in ROUTE_PATTERNS:
        for m in pattern.finditer(src):
            path, methods = _interpret(m, kind)
            if path and (path.startswith("/") or path.startswith("^") or
                         kind.startswith("wp_")):
                routes.append({"path": path, "methods": methods})
    return routes


def extract_routes_from_text(text, rel_path):
    """Scan a whole file's text for routes (handler unknown). Records the line
    number of each route so the scan engine can link it to its handler."""
    routes = []
    for pattern, kind in ROUTE_PATTERNS:
        for m in pattern.finditer(text):
            path, methods = _interpret(m, kind)
            if path and (path.startswith(("/", "^", "r")) or kind.startswith("wp_")):
                lineno = text.count("\n", 0, m.start()) + 1
                routes.append({"path": _normalize(path), "methods": methods,
                               "file": rel_path, "handler": None, "lineno": lineno,
                               "kind": kind})
    return routes


def _interpret(m, kind):
    groups = m.groups()
    if kind == "decorator":
        verb = groups[0].lower()
        path = groups[1]
        methods = _parse_methods(groups[2]) if len(groups) > 2 and groups[2] else METHOD_FROM_VERB.get(verb, ["GET"])
        return path, methods
    if kind in ("call", "php", "rails"):
        verb = groups[0].lower()
        path = groups[1]
        return path, METHOD_FROM_VERB.get(verb, ["GET"])
    if kind == "spring":
        verb = groups[0].lower()
        path = groups[1]
        return path, METHOD_FROM_VERB.get(verb, ["GET"])
    if kind == "django":
        return groups[1], ["GET", "POST"]
    if kind == "go_mux":
        return groups[0], ["GET", "POST"]
    if kind == "webrick":
        return groups[0], ["GET", "POST"]
    # ---- WordPress hooks () ------------------------------------------
    if kind == "wp_rest":
        # namespace + path -> /wp-json/{namespace}{path}
        return f"/wp-json/{groups[0]}{groups[1]}", ["GET", "POST"]
    if kind == "wp_ajax":
        # /wp-admin/admin-ajax.php?action=X (authenticated)
        return f"/wp-admin/admin-ajax.php?action={groups[0]}", ["GET", "POST"]
    if kind == "wp_ajax_nopriv":
        # /wp-admin/admin-ajax.php?action=X (public)
        return f"/wp-admin/admin-ajax.php?action={groups[0]}", ["GET", "POST"]
    if kind == "wp_menu":
        # /wp-admin/admin.php?page=slug
        return f"/wp-admin/admin.php?page={groups[0]}", ["GET", "POST"]
    if kind == "wp_submenu":
        return f"/wp-admin/admin.php?page={groups[0]}", ["GET", "POST"]
    return None, ["GET"]


def _parse_methods(methods_str):
    if not methods_str:
        return ["GET"]
    found = re.findall(r'["\'](\w+)["\']', methods_str)
    return [x.upper() for x in found] or ["GET"]


def _normalize(path):
    return path.lstrip("r^").rstrip("$")

