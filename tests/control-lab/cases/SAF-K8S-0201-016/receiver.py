"""Private fixture sink for one inert synthetic audit event."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import threading


DATA = Path("/data")
EVENTS = DATA / "events.jsonl"
LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("receiver " + (fmt % args), flush=True)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ready\n")
            return
        if parsed.path != "/events":
            self.send_error(404)
            return
        audit_id = parse_qs(parsed.query).get("auditID", [None])[0]
        with LOCK:
            rows = [json.loads(line) for line in EVENTS.read_text().splitlines() if line.strip()] if EVENTS.exists() else []
        matches = [row for row in rows if audit_id is None or row.get("auditID") == audit_id]
        body = json.dumps(matches, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/events":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 1 <= size <= 4096:
                raise ValueError("event size outside fixture limit")
            event = json.loads(self.rfile.read(size))
            if not isinstance(event, dict) or event.get("schema") != "saf-k8s-lab/v1":
                raise ValueError("unexpected fixture")
        except ValueError:
            self.send_error(400)
            return
        if not (DATA / "accepting").exists():
            self.send_response(503, "Service Unavailable")
            self.end_headers()
            self.wfile.write(b"unavailable\n")
            print(f"receiver status=503 auditID={event.get('auditID')}", flush=True)
            return
        with LOCK:
            rows = [json.loads(line) for line in EVENTS.read_text().splitlines() if line.strip()] if EVENTS.exists() else []
            if not any(row.get("auditID") == event.get("auditID") for row in rows):
                with EVENTS.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        self.send_response(202, "Accepted")
        self.end_headers()
        self.wfile.write(b"accepted\n")
        print(f"receiver accepted auditID={event.get('auditID')}", flush=True)


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
