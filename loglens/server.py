"""Zero-dependency web server: serves the dashboard and a small JSON API.

GET  /               dashboard
GET  /api/report     the report loaded at start-up (404 if none)
POST /api/analyze    body = raw log text, query ?provider=rules|openai|anthropic
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .llm import AnalysisError, get_provider
from .pipeline import run

DASHBOARD = Path(__file__).resolve().parent.parent / "dashboard" / "index.html"
MAX_BODY = 8 * 1024 * 1024  # 8 MB


def make_handler(report_path: str):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload) -> None:
            self._send(status, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

        def do_GET(self):  # noqa: N802
            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                if not DASHBOARD.exists():
                    return self._json(404, {"error": "dashboard/index.html not found"})
                return self._send(200, DASHBOARD.read_bytes(), "text/html; charset=utf-8")
            if path == "/api/report":
                target = Path(report_path)
                if not target.exists():
                    return self._json(404, {"error": "no report yet; run 'loglens analyze' or upload a log"})
                return self._send(200, target.read_bytes(), "application/json; charset=utf-8")
            return self._json(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path != "/api/analyze":
                return self._json(404, {"error": "not found"})
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                return self._json(400, {"error": "empty body"})
            if length > MAX_BODY:
                return self._json(413, {"error": "log too large (8 MB max)"})
            text = self.rfile.read(length).decode("utf-8", errors="replace")
            name = parse_qs(parsed.query).get("provider", ["rules"])[0]
            try:
                provider = get_provider(name)
                report, _, _ = run(text.splitlines(), provider, source="uploaded log")
            except AnalysisError as exc:
                return self._json(400, {"error": str(exc)})
            if report["meta"]["parsed_records"] == 0:
                return self._json(400, {"error": "no log lines matched the expected format: 'YYYY-MM-DD HH:MM:SS LEVEL component: message'"})
            return self._json(200, report)

        def log_message(self, fmt, *args):  # keep the console quiet
            pass

    return Handler


def serve(report_path: str, port: int = 8000, host: str = "127.0.0.1") -> None:
    server = ThreadingHTTPServer((host, port), make_handler(report_path))
    print(f"LogLens dashboard: http://{host}:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
