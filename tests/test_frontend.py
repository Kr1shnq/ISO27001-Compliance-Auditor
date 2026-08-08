"""
test_frontend.py
----------------
Runs the jsdom frontend suite (tests/test_frontend.js) against a live dev
server, so the browser code is exercised end to end against the real API.

Requires Node and jsdom:
    npm install jsdom            # in the repo root, or set NODE_PATH

Run:  python tests/test_frontend.py
"""

import os
import socket
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "api"))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import dev_server                                    # noqa: E402


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def node_available():
    try:
        subprocess.run(["node", "-e", "require('jsdom')"], check=True,
                       capture_output=True, timeout=60)
        return True
    except Exception:                                # noqa: BLE001
        return False


def main():
    if not node_available():
        print("SKIPPED: Node with jsdom is not available.")
        print("         Install it with:  npm install jsdom")
        return 0

    port = free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), dev_server.Router)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.4)
    print(f"dev server on http://127.0.0.1:{port}")

    try:
        proc = subprocess.run(
            ["node", os.path.join(ROOT, "tests", "test_frontend.js"),
             f"http://127.0.0.1:{port}"],
            cwd=ROOT, timeout=420)
        return proc.returncode
    finally:
        server.shutdown()


if __name__ == "__main__":
    sys.exit(main())
