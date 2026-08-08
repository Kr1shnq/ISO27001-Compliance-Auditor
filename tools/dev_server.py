"""
dev_server.py
-------------
Local stand-in for the Vercel runtime, so the API and frontend can be developed
and tested without deploying.

Routes requests the same way Vercel does:

    /api/<name>   ->  the `handler` class in api/<name>.py
    /*            ->  static files from public/

Run:
    python tools/dev_server.py            # http://localhost:3000
    python tools/dev_server.py --port 8000
"""

from __future__ import annotations

import argparse
import importlib.util
import io
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_DIR = os.path.join(ROOT, "api")
PUBLIC_DIR = os.path.join(ROOT, "public")

sys.path.insert(0, ROOT)
sys.path.insert(0, API_DIR)          # mirrors Vercel: handlers import `_common`

MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
}

_handlers: dict = {}
_lock = threading.Lock()


def load_handler(name: str):
    """Import api/<name>.py and return its `handler` class."""
    with _lock:
        if name in _handlers:
            return _handlers[name]
        path = os.path.join(API_DIR, f"{name}.py")
        if not os.path.isfile(path) or name.startswith("_"):
            return None
        spec = importlib.util.spec_from_file_location(f"api_{name}", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls = getattr(module, "handler", None)
        _handlers[name] = cls
        return cls


class _Capture(io.BytesIO):
    """Collects what the Vercel-style handler writes, so we can relay it."""

    def close(self):                      # keep the buffer readable afterwards
        pass


class Router(BaseHTTPRequestHandler):
    server_version = "ISO27001DevServer/1.0"

    def _serve_api(self, name: str):
        cls = load_handler(name)
        if cls is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"error":"No such endpoint."}')
            return

        # Instantiate the Vercel handler without running BaseHTTPRequestHandler's
        # __init__ (which would try to parse the request all over again), then
        # wire it to this connection's streams.
        inst = cls.__new__(cls)
        inst.rfile = self.rfile
        inst.wfile = self.wfile
        inst.headers = self.headers
        inst.path = self.path
        inst.command = self.command
        inst.request_version = self.request_version
        inst.client_address = self.client_address
        inst.server = self.server
        inst.connection = self.connection
        inst.requestline = self.requestline
        inst.close_connection = True
        method = getattr(inst, f"do_{self.command}", None)
        if method is None:
            self.send_response(405)
            self.end_headers()
            return
        method()

    def _serve_static(self, path: str):
        rel = path.lstrip("/") or "index.html"
        if rel.endswith("/"):
            rel += "index.html"
        full = os.path.normpath(os.path.join(PUBLIC_DIR, rel))
        if not full.startswith(PUBLIC_DIR):          # traversal guard
            self.send_response(403)
            self.end_headers()
            return
        if not os.path.isfile(full):
            full = os.path.join(PUBLIC_DIR, "index.html")   # SPA fallback
            if not os.path.isfile(full):
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"public/index.html not found")
                return
        ext = os.path.splitext(full)[1]
        with open(full, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", MIME.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _route(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            self._serve_api(parsed.path[len("/api/"):].strip("/"))
        else:
            self._serve_static(parsed.path)

    do_GET = do_POST = do_OPTIONS = _route

    def log_message(self, fmt, *args):
        sys.stderr.write(f"  {self.command} {self.path}\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=3000)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    srv = ThreadingHTTPServer((args.host, args.port), Router)
    print(f"ISO 27001 Compliance Auditor - dev server")
    print(f"  static : {PUBLIC_DIR}")
    print(f"  api    : {API_DIR}")
    print(f"  http://{args.host}:{args.port}    (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
