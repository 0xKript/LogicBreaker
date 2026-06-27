"""Test that the patched code's routes actually work correctly."""
import sys
import os
import tempfile
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.test_e2e_verification import USER_CODE, RealisticMockLLM
from agents.ai_pipeline import AIPipeline


HARNESS = '''import importlib.util, sys, os
spec = importlib.util.spec_from_file_location("app", MODPATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
app = m.app

# create the uploads dir so /write does not 500 on missing dir
os.makedirs(UPLOADS_DIR, exist_ok=True)

with app.test_client() as c:
    # 1. /hash -- should work
    r = c.get("/hash?text=hello")
    print("HASH:", r.status_code, len(r.get_data()) > 0)

    # 2. /yaml -- should work with safe YAML (no TypeError)
    r = c.post("/yaml", data=b"a: 1\\nb: 2")
    body = r.get_data(as_text=True)
    print("YAML:", r.status_code, r.status_code < 500, repr(body[:50]))

    # 3. /debug -- should return generic 500, NOT leak "division by zero"
    r = c.get("/debug")
    body = r.get_data(as_text=True)
    print("DEBUG:", r.status_code, "internal error" in body.lower(),
          "division by zero" not in body.lower())

    # 4. /write with traversal -- secure_filename NEUTRALISES it
    # (file written with a SAFE name like 'etc_passwd', not at /etc/passwd)
    r = c.get("/write?name=../../../etc/passwd")
    body = r.get_data(as_text=True)
    print("WRITE_TRAVERSAL:", r.status_code, r.status_code < 500,
          "saved" in body or "invalid" in body or "forbidden" in body)

    # 5. /write with safe name -- should work
    r = c.get("/write?name=test.txt")
    body = r.get_data(as_text=True)
    file_written = os.path.exists(os.path.join(UPLOADS_DIR, "test.txt"))
    print("WRITE_SAFE:", r.status_code, "saved" in body, file_written)

    # 6. /temp -- should work, return a path (mkstemp)
    r = c.get("/temp")
    body = r.get_data(as_text=True)
    print("TEMP:", r.status_code, len(body) > 0)

    # 7. /fetch with internal IP -- should be blocked (403)
    r = c.get("/fetch?url=http://127.0.0.1/")
    print("FETCH_BLOCKED:", r.status_code, r.status_code == 403)

    # 8. /fetch with a 172.16.x.x IP -- should ALSO be blocked ( catches this)
    r = c.get("/fetch?url=http://172.16.0.1/")
    print("FETCH_172_BLOCKED:", r.status_code, r.status_code == 403)
'''


def main():
    # 1. generate the patched code via 
    print("[1] Generating patched code via ..")
    mock = RealisticMockLLM()
    pipeline = AIPipeline(mock, language="python", max_fix_retries=0)
    report = pipeline.analyze(USER_CODE, file_path="app.py", do_fix=True)
    patched = report.patched_code

    # use a writable uploads dir for the test (the  fix uses /var/www/uploads
    # which is correct in production; for the test we point it at /tmp)
    test_uploads = os.path.join(tempfile.gettempdir(), "test_uploads")
    os.makedirs(test_uploads, exist_ok=True)
    patched = patched.replace('/var/www/uploads', test_uploads)

    # 2. write the patched code + harness to a temp dir
    with tempfile.TemporaryDirectory() as td:
        modpath = os.path.join(td, "app.py")
        with open(modpath, "w") as f:
            f.write(patched)
        runner = os.path.join(td, "run.py")
        harness = HARNESS.replace("MODPATH", repr(modpath)).replace("UPLOADS_DIR", repr(test_uploads))
        with open(runner, "w") as f:
            f.write(harness)
        env = dict(os.environ)
        env["PYTHONPATH"] = sys.prefix + os.pathsep + env.get("PYTHONPATH", "")

        # 3. run the harness
        print("\n[2] Testing patched routes...\n")
        p = subprocess.run([sys.executable, runner], cwd=td, env=env,
                           capture_output=True, text=True, timeout=30)
        print(p.stdout)
        if p.stderr:
            print("STDERR:", p.stderr[:500])

    # 4. interpret the results
    print("\n" + "=" * 60)
    print("  Route Test Results")
    print("=" * 60)
    lines = p.stdout.strip().split("\n") if p.stdout else []
    passed = 0
    failed = 0
    for line in lines:
        if not line.startswith(("HASH:", "YAML:", "DEBUG:", "WRITE_",
                                "TEMP:", "FETCH_")):
            continue
        # parse the line: NAME: status bool1 bool2 ...
        parts = line.split(":", 1)
        name = parts[0].strip()
        rest = parts[1].strip() if len(parts) > 1 else ""
        # the last "True/False" indicators must all be True for pass
        tokens = rest.split()
        bools = [t == "True" for t in tokens if t in ("True", "False")]
        ok = all(bools) if bools else False
        marker = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1
        print(f"  [{marker}] {name:20s} {rest}")
    print("=" * 60)
    print(f"  {passed} passed, {failed} failed")
    print("=" * 60)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
