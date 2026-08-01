#!/usr/bin/env python3
"""The local web app: stdlib HTTP server, JSON API, built Vue frontend.

    python3 web/server.py                  # then open http://127.0.0.1:8000

Only the standard library is used here, so the app runs with nothing installed
beyond the three frozen Python dependencies. The frontend under web/static is
built from web/ui; see the README for the npm commands that regenerate it.
"""

import argparse
import json
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from web.service import (
    AGENT_KINDS,
    MAX_CHUNKS,
    MAX_RUNS,
    MAX_TEXT,
    InvalidInput,
    apply_tamper,
    build_session,
    default_input,
    rebuild_session,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
SESSIONS_DIR = Path(__file__).resolve().parents[1] / "out" / "web-sessions"

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json; charset=utf-8",
    ".woff2": "font/woff2",
}


def make_server(host, port, sessions_dir):
    """Build the HTTP server; ``port`` 0 picks a free one, which tests rely on."""
    handler = _make_handler(Path(sessions_dir))
    server = ThreadingHTTPServer((host, port), handler)
    server.quiet = True
    return server


def _make_handler(sessions_dir):
    class Handler(BaseHTTPRequestHandler):
        server_version = "attest-web"
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.path.split("?")[0] == "/api/defaults":
                return self._json(200, _defaults())
            return self._static(self.path.split("?")[0])

        def do_POST(self):
            actions = {
                "/api/episode": lambda body: build_session(sessions_dir, body),
                "/api/tamper": lambda body: apply_tamper(
                    sessions_dir, body.get("session"), body.get("tamper")
                ),
                "/api/rebuild": lambda body: rebuild_session(sessions_dir, body.get("session")),
            }
            action = actions.get(self.path.split("?")[0])
            if action is None:
                return self._json(404, {"error": "no such endpoint"})
            try:
                body = self._body()
            except ValueError:
                return self._json(400, {"error": "the request body was not valid JSON"})
            try:
                return self._json(200, action(body))
            except InvalidInput as error:
                return self._json(400, {"error": str(error)})

        def log_message(self, fmt, *args):
            if self.server.quiet:
                return
            sys.stderr.write(f"  {self.address_string()} {fmt % args}\n")

        def _body(self):
            length = int(self.headers.get("Content-Length") or 0)
            if not length:
                return {}
            return json.loads(self.rfile.read(length).decode("utf-8"))

        def _json(self, status, payload):
            self._send(status, json.dumps(payload).encode("utf-8"), CONTENT_TYPES[".json"])

        def _static(self, path):
            relative = "index.html" if path == "/" else path.lstrip("/")
            target = (STATIC_DIR / relative).resolve()
            if not target.is_relative_to(STATIC_DIR.resolve()) or not target.is_file():
                return self._json(404, {"error": f"not found: {path}"})
            content_type = CONTENT_TYPES.get(target.suffix, "application/octet-stream")
            self._send(200, target.read_bytes(), content_type)

        def _send(self, status, body, content_type):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return Handler


def _defaults():
    return {
        "input": default_input(),
        "agents": list(AGENT_KINDS),
        "limits": {"max_chunks": MAX_CHUNKS, "max_runs": MAX_RUNS, "max_text": MAX_TEXT},
    }


def main(argv=None):
    args = _parse_args(argv)
    server = make_server(args.host, args.port, args.sessions)
    server.quiet = args.quiet
    url = f"http://{args.host}:{server.server_address[1]}"
    print(f"attested episodes: {url}")
    print(f"  sessions in {args.sessions}")
    print("  ctrl-c to stop")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return 0


def _parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--sessions", default=str(SESSIONS_DIR), help="where bundles are written")
    parser.add_argument("--open", action="store_true", help="open a browser window")
    parser.add_argument("--quiet", action="store_true", help="do not log requests")
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
