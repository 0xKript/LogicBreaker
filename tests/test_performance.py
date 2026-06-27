#!/usr/bin/env python3
"""
LogicBreaker AI -- Performance Benchmark
=========================================

Measures:
  - Speed: N files in X seconds
  - Cache hit rate
  - Parallelism efficiency

Compares parallel + cache vs sequential.
"""

import sys
import os
import time
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.batch_processor import BatchProcessor


def generate_test_files(n: int, target_dir: str):
    """Generate N test Python files with mixed vulnerabilities."""
    templates = [
        "import sqlite3\ndef f{i}():\n    q = 'SELECT * FROM u WHERE id=' + __import__('flask').request.args['id']\n    sqlite3.connect('x').cursor().execute(q)\n",
        "import hashlib\ndef f{i}():\n    return hashlib.md5('x'.encode()).hexdigest()\n",
        "import hashlib\ndef f{i}():\n    return hashlib.sha256('x'.encode()).hexdigest()\n",
        "import os\ndef f{i}():\n    os.system('echo ' + __import__('flask').request.args['x'])\n",
        "API_KEY = 'sk-secret-{i}'\n",
    ]
    files = []
    for i in range(n):
        tpl = templates[i % len(templates)]
        path = os.path.join(target_dir, f"file_{i:05d}.py")
        with open(path, "w") as f:
            f.write(tpl.format(i=i))
        files.append({"path": path, "language": "python",
                      "rel_path": f"file_{i:05d}.py"})
    return files


def benchmark(n_files: int = 100):
    """Benchmark batch processing on N files."""
    print(f"\n[+] Benchmarking on {n_files} files...")

    with tempfile.TemporaryDirectory() as td:
        files = generate_test_files(n_files, td)
        print(f"    Generated {len(files)} files")

        def fake_scan(path, language):
            time.sleep(0.05)
            return [{"cwe": "CWE-89", "name": "SQL Injection",
                     "file": path, "line": 3, "severity": "CRITICAL"}]

        bp = BatchProcessor(max_workers=8)
        bp.clear_cache()

        t0 = time.time()
        result = bp.run(files, fake_scan, progress_callback=None)
        parallel_time = time.time() - t0
        parallel_findings = len(result["findings"])
        parallel_cached = result["progress"].skipped

        t0 = time.time()
        result2 = bp.run(files, fake_scan, progress_callback=None)
        cached_time = time.time() - t0
        cached_count = result2["progress"].skipped

        t0 = time.time()
        seq_findings = 0
        for f in files:
            seq_findings += len(fake_scan(f["path"], f["language"]))
        seq_time = time.time() - t0

    print(f"\n  {'Metric':<30s}  {'Sequential':>15s}  {'Parallel':>15s}  {'Cached':>15s}")
    print(f"  {'-'*30}  {'-'*15}  {'-'*15}  {'-'*15}")
    print(f"  {'Time (sec)':<30s}  {seq_time:>15.2f}  {parallel_time:>15.2f}  {cached_time:>15.2f}")
    print(f"  {'Speedup':<30s}  {1.0:>15.1f}x  {seq_time/parallel_time:>14.1f}x  {seq_time/cached_time:>14.1f}x")
    print(f"  {'Findings':<30s}  {seq_findings:>15d}  {parallel_findings:>15d}  {result2['progress'].findings:>15d}")
    print(f"  {'Cache hits':<30s}  {0:>15d}  {parallel_cached:>15d}  {cached_count:>15d}")

    return {
        "n_files": n_files,
        "seq_time_sec": round(seq_time, 2),
        "parallel_time_sec": round(parallel_time, 2),
        "cached_time_sec": round(cached_time, 2),
        "parallel_speedup": round(seq_time / parallel_time, 1),
        "cached_speedup": round(seq_time / cached_time, 1),
    }


def main():
    print("=" * 78)
    print("  LogicBreaker AI -- Performance Benchmark")
    print("=" * 78)

    r100 = benchmark(100)
    r500 = benchmark(500)

    print("\n" + "=" * 78)
    print("  PERFORMANCE SUMMARY")
    print("=" * 78)
    print(f"  100 files: parallel {r100['parallel_speedup']}x faster, cached {r100['cached_speedup']}x faster")
    print(f"  500 files: parallel {r500['parallel_speedup']}x faster, cached {r500['cached_speedup']}x faster")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
