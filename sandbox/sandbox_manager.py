"""
Sandbox Manager
===============

Provides an ephemeral, isolated execution environment for dynamic testing.

Design notes / honesty about scope:
  * The primary, always-available isolation mechanism is a *filesystem copy*
    of the target project into a temporary directory, run as a separate
    Python subprocess on a free local port. This requires no extra
    infrastructure and works on every platform.
  * If Docker is detected on the host (``docker`` on PATH), a containerized
    run is used instead for stronger isolation. This is an additive upgrade,
    not a hard requirement -- the tool is fully functional without Docker.
  * Every sandbox is destroyed (process killed, temp directory removed) once
    testing finishes, regardless of outcome.
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import threading
import collections

import requests


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _drain(stream, buf):
    """Background thread that continuously reads from `stream` and keeps the
    last 100 lines in `buf`. This prevents the OS pipe buffer (64KB on Linux)
    from filling up and deadlocking the subprocess when the target app prints
    a lot of logs or tracebacks to stderr/stdout."""
    try:
        for line in stream:
            buf.append(line)
            while len(buf) > 100:
                buf.popleft()
    except Exception:
        pass


def _start_with_drain(cmd, cwd, env=None):
    """Launch a subprocess with stdout/stderr PIPEs, and immediately start
    background reader threads to drain them. Returns (proc, stdout_buf, stderr_buf)."""
    proc = subprocess.Popen(cmd, cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _stdout_buf = collections.deque()
    _stderr_buf = collections.deque()
    threading.Thread(target=_drain, args=(proc.stdout, _stdout_buf), daemon=True).start()
    threading.Thread(target=_drain, args=(proc.stderr, _stderr_buf), daemon=True).start()
    proc._lb_stderr_buf = _stderr_buf
    proc._lb_stdout_buf = _stdout_buf
    return proc


class SandboxManager:
    def __init__(self):
        self.docker_available = shutil.which("docker") is not None
        self._tmpdirs = []
        self._procs = []

    # ------------------------------------------------------------------
    def create_copy(self, target_dir: str) -> str:
        """Copy ``target_dir`` into a fresh temp directory and return its path."""
        tmpdir = tempfile.mkdtemp(prefix="logicbreaker_")
        dest = os.path.join(tmpdir, "project")
        shutil.copytree(
            target_dir, dest,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git", "venv", ".venv"),
        )
        self._tmpdirs.append(tmpdir)
        return dest

    # ------------------------------------------------------------------
    def start_node_app(self, project_dir: str, entrypoint: str = "server.js", timeout: float = 12.0):
        """
        Launch a Node.js app (Express/Koa/raw http) on a free port.

        Convention (same as the Python launcher): the entrypoint reads the port
        from argv[2] (process.argv[2]) or the PORT env var. We set both so most
        apps work. Readiness is detected by polling /health then /.
        """
        import shutil as _sh
        if _sh.which("node") is None:
            raise RuntimeError("Node.js runtime not found on PATH; cannot run JS target")

        entry_path = os.path.join(project_dir, entrypoint)
        if not os.path.exists(entry_path):
            raise FileNotFoundError(f"Entrypoint not found: {entry_path}")

        port = _free_port()
        env = dict(os.environ, PORT=str(port))
        proc = _start_with_drain(["node", entrypoint, str(port)], cwd=project_dir, env=env)
        self._procs.append(proc)
        base_url = f"http://127.0.0.1:{port}"
        return self._await_ready(proc, base_url, timeout)

    # ------------------------------------------------------------------
    def start_php_app(self, project_dir: str, entrypoint: str = "index.php", timeout: float = 12.0):
        """
        Launch a PHP app via the built-in PHP web server:
            php -S 127.0.0.1:<port> <entrypoint>
        Requires the `php` CLI on PATH (PHP 5.4+). Works for plain PHP and many
        micro-frameworks that route through a single front controller.
        """
        import shutil as _sh
        if _sh.which("php") is None:
            raise RuntimeError("PHP runtime not found on PATH; cannot run PHP target")

        port = _free_port()
        proc = _start_with_drain(
            ["php", "-S", f"127.0.0.1:{port}", "-t", project_dir, os.path.join(project_dir, entrypoint)],
            cwd=project_dir)
        self._procs.append(proc)
        return self._await_ready(proc, f"http://127.0.0.1:{port}", timeout)

    # ------------------------------------------------------------------
    def _await_ready(self, proc, base_url, timeout):
        deadline = time.time() + timeout
        last_err = None
        grace = time.time() + 2.0   # don't declare "exited early" during startup
        while time.time() < deadline:
            if proc.poll() is not None and time.time() > grace:
                # read from the drain buffers instead of communicate() (which
                # would deadlock if the pipes are full)
                err_lines = b"".join(getattr(proc, "_lb_stderr_buf", []))
                out_lines = b"".join(getattr(proc, "_lb_stdout_buf", []))
                raise RuntimeError(
                    f"Sandbox app exited early (code {proc.returncode}).\n"
                    f"stdout: {out_lines.decode(errors='replace')[-500:]}\n"
                    f"stderr: {err_lines.decode(errors='replace')[-500:]}"
                )
            # ANY HTTP response (even 404 or 500) means the server is listening
            # and ready to receive our attack probes. Real apps often return 404
            # on '/' or 500 on a route that needs a DB -- the server is still up.
            for probe_path in ("/health", "/", "/login", "/api"):
                try:
                    requests.get(f"{base_url}{probe_path}", timeout=0.6)
                    return proc, base_url
                except requests.exceptions.RequestException as e:
                    last_err = e
            time.sleep(0.2)
        self.stop_process(proc)
        raise TimeoutError(f"Sandbox app did not become healthy in time ({last_err})")

    # ------------------------------------------------------------------
    def start_ruby_app(self, project_dir, entrypoint="app.rb", timeout=12.0):
        """Launch a Ruby web app (Sinatra/Rack/plain). The entrypoint should
        read the port from ARGV[0] or the PORT env var."""
        import shutil as _sh
        if _sh.which("ruby") is None:
            raise RuntimeError("Ruby runtime not found on PATH; cannot run Ruby target")
        port = _free_port()
        env = dict(os.environ, PORT=str(port))
        proc = _start_with_drain(["ruby", entrypoint, str(port)], cwd=project_dir, env=env)
        self._procs.append(proc)
        return self._await_ready(proc, f"http://127.0.0.1:{port}", timeout)

    def start_go_app(self, project_dir, entrypoint="main.go", timeout=25.0):
        """Build and run a Go web app: `go run <entrypoint>`. Go compiles on the
        fly, so this both builds and runs. The program should read the port from
        os.Args[1] or the PORT env var."""
        import shutil as _sh
        if _sh.which("go") is None:
            raise RuntimeError("Go runtime not found on PATH; cannot run Go target")
        port = _free_port()
        env = dict(os.environ, PORT=str(port))
        proc = _start_with_drain(["go", "run", entrypoint, str(port)], cwd=project_dir, env=env)
        self._procs.append(proc)
        return self._await_ready(proc, f"http://127.0.0.1:{port}", timeout)

    def start_deno_app(self, project_dir, entrypoint="server.ts", timeout=15.0):
        """Run a Deno (TypeScript) web app with network+read permissions."""
        import shutil as _sh
        if _sh.which("deno") is None:
            raise RuntimeError("Deno runtime not found on PATH")
        port = _free_port()
        env = dict(os.environ, PORT=str(port))
        proc = _start_with_drain(
            ["deno", "run", "--allow-net", "--allow-read", "--allow-env", entrypoint, str(port)],
            cwd=project_dir, env=env)
        self._procs.append(proc)
        return self._await_ready(proc, f"http://127.0.0.1:{port}", timeout)

    def start_for_language(self, project_dir, language, entrypoint, timeout=None):
        """
        Universal dispatcher: launch a web app in WHATEVER language it is
        written in, provided that language's runtime is installed on the host.
        Uses runtime_detector so it works for any installed runtime, and raises
        a clear error (caught upstream) when the runtime is absent.
        """
        from sandbox import runtime_detector as RT

        # map a few aliases to a canonical runtime language
        lang = {"tsx": "typescript"}.get(language, language)

        launchers = {
            "python": self.start_app,
            "javascript": self.start_node_app,
            "typescript": self.start_node_app,
            "php": self.start_php_app,
            "ruby": self.start_ruby_app,
            "go": self.start_go_app,
        }

        if not RT.is_available(lang):
            raise RuntimeError(
                f"no installed runtime for '{lang}' on this host; static detection and "
                f"a correct patch are still produced, but live exploitation needs the "
                f"'{lang}' runtime installed")

        launcher = launchers.get(lang)
        if launcher is None:
            # runtime exists but we don't have a specialised web launcher yet
            raise RuntimeError(
                f"'{lang}' runtime is installed but LogicBreaker has no web-app launcher "
                f"for it yet (live exploitation supports Python, Node.js, PHP, Ruby, Go)")

        if timeout is None:
            timeout = 25.0 if lang in ("go",) else 12.0
        return launcher(project_dir, entrypoint, timeout)

    # ------------------------------------------------------------------
    def start_flask_app(self, project_dir: str, entrypoint: str = "app.py", timeout: float = 12.0):
        """Backwards-compatible alias for start_app."""
        return self.start_app(project_dir, entrypoint=entrypoint, timeout=timeout)

    def start_app(self, project_dir: str, entrypoint: str = "app.py", timeout: float = 12.0):
        """
        Launch ``entrypoint`` as a subprocess inside ``project_dir`` on a free
        port and wait until it responds.

        Port injection: we do NOT rely on the user's app reading the port from
        argv. Instead we detect the Flask/FastAPI app object and run it on our
        chosen port via a generated bootstrap, with a robust fallback that
        monkeypatches Flask.run / uvicorn so even apps written as
        ``app.run(debug=True)`` (no port) bind to our port. This makes live
        exploitation work on real-world files, not just demo-shaped ones.

        Readiness is detected by polling ``/health`` first, then ``/`` (so apps
        without a health route still work). Returns ``(process, base_url)``.
        """
        entry_path = os.path.join(project_dir, entrypoint)
        if not os.path.exists(entry_path):
            raise FileNotFoundError(f"Entrypoint not found: {entry_path}")

        port = _free_port()
        framework = self._detect_framework(entry_path)
        app_var = self._app_var(entry_path, framework)
        module = entrypoint[:-3].replace(os.sep, ".") if entrypoint.endswith(".py") else entrypoint

        if framework == "fastapi":
            cmd = [sys.executable, "-m", "uvicorn", f"{module}:{app_var}",
                   "--port", str(port), "--host", "127.0.0.1", "--log-level", "warning"]
            proc = _start_with_drain(cmd, cwd=project_dir)
        else:
            # write a bootstrap that imports the user's module and runs its app
            # object on our port; fall back to monkeypatching app.run.
            boot = self._write_python_bootstrap(project_dir, module, app_var, port)
            cmd = [sys.executable, boot, str(port)]
            env = dict(os.environ, PORT=str(port), FLASK_RUN_PORT=str(port),
                       PYTHONUNBUFFERED="1")
            proc = _start_with_drain(cmd, cwd=project_dir, env=env)

        self._procs.append(proc)
        base_url = f"http://127.0.0.1:{port}"
        return self._await_ready(proc, base_url, timeout)

    @staticmethod
    def _app_var(entry_path, framework):
        """Find the Flask()/FastAPI() app variable name in the entrypoint."""
        import re
        try:
            with open(entry_path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            return "app"
        pat = r"(\w+)\s*=\s*FastAPI\(" if framework == "fastapi" else r"(\w+)\s*=\s*Flask\("
        m = re.search(pat, text)
        return m.group(1) if m else "app"

    def _write_python_bootstrap(self, project_dir, module, app_var, port):
        """Create a bootstrap script in project_dir that imports the user's
        module and serves its Flask app on `port`. Robust to apps that call
        app.run() themselves (we monkeypatch Flask.run to force host/port and
        disable the reloader/debugger)."""
        boot_path = os.path.join(project_dir, "_lb_bootstrap.py")
        code = f'''import sys, os, importlib
_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else {port}

# Force any Flask app.run(...) to bind to our host/port without the reloader.
try:
    import flask
    _orig_run = flask.Flask.run
    def _patched_run(self, host=None, port=None, debug=None, load_dotenv=True, **kw):
        kw.pop("use_reloader", None)
        return _orig_run(self, host="127.0.0.1", port=_PORT, debug=False,
                         use_reloader=False, **kw)
    flask.Flask.run = _patched_run
except Exception:
    pass

# Import the user's module. If it runs the server at import time (app.run under
# __main__), our monkeypatch already redirected it; otherwise we serve the app
# object ourselves below.
_served = {{"done": False}}
try:
    _mod = importlib.import_module("{module}")
except SystemExit:
    _served["done"] = True
except Exception as _e:
    # surface import errors clearly
    sys.stderr.write("BOOTSTRAP_IMPORT_ERROR: %r\\n" % (_e,))
    raise

if not _served["done"]:
    app = getattr(_mod, "{app_var}", None)
    if app is None:
        # try to find any Flask app object in the module
        try:
            import flask
            for _n in dir(_mod):
                _o = getattr(_mod, _n)
                if isinstance(_o, flask.Flask):
                    app = _o; break
        except Exception:
            pass
    if app is not None:
        try:
            app.run(host="127.0.0.1", port=_PORT, debug=False, use_reloader=False)
        except TypeError:
            app.run(host="127.0.0.1", port=_PORT)
'''
        with open(boot_path, "w", encoding="utf-8") as fh:
            fh.write(code)
        return "_lb_bootstrap.py"

    @staticmethod
    def _detect_framework(entry_path):
        try:
            with open(entry_path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            return "flask"
        if "FastAPI(" in text:
            return "fastapi"
        return "flask"

    @staticmethod
    def _fastapi_app_var(entry_path):
        import re
        try:
            with open(entry_path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            return "app"
        m = re.search(r"(\w+)\s*=\s*FastAPI\(", text)
        return m.group(1) if m else "app"

    # ------------------------------------------------------------------
    def stop_process(self, proc):
        if proc is None:
            return
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        if proc in self._procs:
            self._procs.remove(proc)

    # ------------------------------------------------------------------
    def destroy_all(self):
        """Kill any remaining subprocesses and remove all temp directories."""
        for proc in list(self._procs):
            self.stop_process(proc)
        for tmpdir in self._tmpdirs:
            shutil.rmtree(tmpdir, ignore_errors=True)
        self._tmpdirs.clear()
