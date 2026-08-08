"""
run_all.py
----------
Runs every verification suite in one go:

    test_engine.py     audit engine, ingestion, scoring, roadmap, PDF
    test_api.py        the three Vercel serverless endpoints
    test_frontend.py   the browser app in jsdom, against a live API
                       (skipped automatically if Node/jsdom is unavailable)

Run:  python tests/run_all.py
"""

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SUITES = [
    ("Audit engine", "test_engine.py"),
    ("Serverless API", "test_api.py"),
    ("Frontend (jsdom)", "test_frontend.py"),
]


def main():
    results = []
    for label, script in SUITES:
        print(f"\n{'=' * 62}\n  {label}  —  tests/{script}\n{'=' * 62}")
        started = time.time()
        proc = subprocess.run([sys.executable, os.path.join(HERE, script)],
                              capture_output=True, text=True, timeout=600)
        out = proc.stdout
        # Echo the tail so failures are visible without drowning the console.
        tail = out.strip().splitlines()
        print("\n".join(tail[-14:]) if len(tail) > 14 else out.strip())
        if proc.stderr.strip():
            print(proc.stderr.strip()[-800:], file=sys.stderr)
        skipped = "SKIPPED" in out
        results.append((label, proc.returncode, skipped, time.time() - started))

    print(f"\n{'=' * 62}\n  SUMMARY\n{'=' * 62}")
    failures = 0
    for label, rc, skipped, secs in results:
        state = "SKIP" if skipped else ("PASS" if rc == 0 else "FAIL")
        if rc != 0 and not skipped:
            failures += 1
        print(f"  [{state}] {label:<22} {secs:5.1f}s")
    print("=" * 62)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
