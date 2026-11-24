"""Small case-owned TLS receiver for synthetic Kubernetes audit events."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
from threading import Lock
from urllib.parse import urlsplit


DATA = Path("/data")
EVENTS = DATA / "events.jsonl"
ATTEMPTS = DATA / "attempts.jsonl"
LOCK = Lock()
FAIL_NEXT = False
MAX_BODY = 262144


def append(path, value):
    with LOCK, path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def read_lines(path):
    if not path.exists():
        return []
    with LOCK:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def respond(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        if body:
            self.send_header("Content-Type", "application/json")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/healthz":
            self.respond(200, b"ready")
            return
        if path != "/__case/snapshot":
            self.respond(404)
            return
        body = json.dumps({"events": read_lines(EVENTS), "attempts": read_lines(ATTEMPTS)},
                          separators=(",", ":")).encode()
        self.respond(200, body)

    def do_POST(self):
        global FAIL_NEXT
        path = urlsplit(self.path).path
        if path == "/__case/fail-next":
            FAIL_NEXT = True
            self.respond(200, b"armed")
            return
        if path != "/":
            self.respond(404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= MAX_BODY:
                raise ValueError("invalid body length")
            payload = json.loads(self.rfile.read(length))
            if payload.get("apiVersion") != "audit.k8s.io/v1" or payload.get("kind") != "EventList":
                raise ValueError("expected audit.k8s.io/v1 EventList")
            events = payload.get("items")
            if not isinstance(events, list) or not events:
                raise ValueError("expected nonempty EventList.items")
            for event in events:
                if (not isinstance(event, dict) or not event.get("auditID")
                        or event.get("level") != "Metadata"
                        or event.get("stage") != "ResponseComplete"
                        or event.get("verb") != "create"
                        or (event.get("objectRef") or {}).get("resource") != "configmaps"
                        or (event.get("objectRef") or {}).get("namespace") != "saf-test"
                        or "requestObject" in event or "responseObject" in event):
                    raise ValueError("batch contains an out-of-scope audit event")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, AttributeError) as error:
            print("Rejected synthetic audit batch:", error, flush=True)
            self.respond(400)
            return

        ids = [event["auditID"] for event in events]
        if FAIL_NEXT:
            FAIL_NEXT = False
            append(ATTEMPTS, {"status": 503, "audit_ids": ids})
            self.respond(503)
            return

        for event in events:
            append(EVENTS, event)
        append(ATTEMPTS, {"status": 200, "audit_ids": ids})
        self.respond(200)


def main():
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
