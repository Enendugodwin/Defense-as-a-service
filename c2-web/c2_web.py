import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

import requests

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000").rstrip("/")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")
WEB_HOST = os.getenv("C2_WEB_HOST", "127.0.0.1")
WEB_PORT = int(os.getenv("C2_WEB_PORT", "8081"))
HTML = Path(__file__).with_name("console.html")


def call_api(method, path, *, body=None, params=None):
    if not ADMIN_API_KEY:
        return 503, {"detail": "C2 web console admin key is not configured"}
    try:
        response = requests.request(
            method,
            API_URL + path,
            headers={"x-api-key": ADMIN_API_KEY},
            json=body,
            params=params,
            timeout=(3, 15),
        )
    except requests.RequestException as exc:
        return 502, {"detail": "Ingest API unavailable", "error": type(exc).__name__}
    try:
        payload = response.json()
    except ValueError:
        payload = {"detail": f"Ingest API returned HTTP {response.status_code}"}
    return response.status_code, payload


class Handler(BaseHTTPRequestHandler):
    server_version = "DefensiveConsole/1"

    def _send(self, status, payload, content_type="application/json; charset=utf-8"):
        if isinstance(payload, str):
            body = payload.encode("utf-8")
        else:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        if not self.headers.get("Content-Type", "").lower().startswith("application/json"):
            raise ValueError("Content-Type must be application/json")
        size = int(self.headers.get("Content-Length", "0"))
        if size < 1 or size > 8192:
            raise ValueError("Request body size is invalid")
        data = json.loads(self.rfile.read(size))
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            try:
                self._send(200, HTML.read_text(encoding="utf-8"), "text/html; charset=utf-8")
            except OSError:
                self._send(500, {"detail": "Console page unavailable"})
            return
        if parsed.path == "/api/agents":
            status, payload = call_api("GET", "/admin/agents")
            self._send(status, payload)
            return
        match = re.fullmatch(r"/api/sessions/([A-Za-z0-9_-]+)", parsed.path)
        if match:
            query = parse_qs(parsed.query)
            try:
                after_id = max(0, int(query.get("after_id", ["0"])[0]))
            except ValueError:
                self._send(400, {"detail": "after_id must be an integer"})
                return
            session_id = quote(match.group(1), safe="")
            status, payload = call_api("GET", f"/sessions/{session_id}", params={"after_id": after_id})
            self._send(status, payload)
            return
        self._send(404, {"detail": "Not found"})

    def do_POST(self):
        parsed = urlsplit(self.path)
        try:
            body = self._body()
        except (ValueError, json.JSONDecodeError):
            self._send(400, {"detail": "Invalid JSON request"})
            return
        if parsed.path == "/api/sessions":
            status, payload = call_api("POST", "/sessions", body=body)
            self._send(status, payload)
            return
        match = re.fullmatch(r"/api/sessions/([A-Za-z0-9_-]+)/(input|close)", parsed.path)
        if match:
            session_id = quote(match.group(1), safe="")
            action = match.group(2)
            if action == "input":
                status, payload = call_api("POST", f"/sessions/{session_id}/input", body=body)
            else:
                status, payload = call_api("DELETE", f"/sessions/{session_id}")
            self._send(status, payload)
            return
        self._send(404, {"detail": "Not found"})

    def log_message(self, format_string, *args):
        # Avoid logging command payloads or API credentials.
        return


def main():
    if not ADMIN_API_KEY:
        raise SystemExit("Set ADMIN_API_KEY in the web-console environment")
    server = ThreadingHTTPServer((WEB_HOST, WEB_PORT), Handler)
    print(f"C2 web console listening on http://{WEB_HOST}:{WEB_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()