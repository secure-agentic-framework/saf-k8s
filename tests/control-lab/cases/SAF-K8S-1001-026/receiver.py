"""Case-owned TLS audit webhook receiver with file-backed event retention."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import sys
from threading import Lock
from urllib.parse import urlsplit


STORE = Path("/data/audit-events.jsonl")
STORE_LOCK = Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ready")
            return
        if self.path != "/snapshot":
            self.send_error(404)
            return
        events = []
        with STORE_LOCK:
            if STORE.exists():
                lines = STORE.read_text(encoding="utf-8").splitlines()
                events = [json.loads(line) for line in lines if line]
        body = json.dumps(events, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if urlsplit(self.path).path != "/":
            print("Unexpected audit webhook path", self.path, flush=True)
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 1_048_576:
                raise ValueError("invalid body length")
            payload = json.loads(self.rfile.read(length))
            if payload.get("apiVersion") != "audit.k8s.io/v1" or payload.get("kind") != "EventList":
                raise ValueError("expected audit.k8s.io/v1 EventList")
            events = payload.get("items")
            if not isinstance(events, list) or not events:
                raise ValueError("expected nonempty EventList.items")
            for event in events:
                if not isinstance(event, dict) or not event.get("auditID"):
                    raise ValueError("each audit event must have an auditID")
                if "requestObject" in event or "responseObject" in event:
                    raise ValueError("metadata policy must not send request or response bodies")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, AttributeError) as error:
            print("Rejected fixture audit batch:", error, flush=True)
            self.send_error(400)
            return

        # Preserve the exact received event JSON as one durable line per event.
        with STORE_LOCK, STORE.open("a", encoding="utf-8") as stream:
            for event in events:
                stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


def main():
    if sys.argv[1:] == ["snapshot"]:
        print(STORE.read_text(encoding="utf-8") if STORE.exists() else "[]")
        return
    if sys.argv[1:]:
        raise SystemExit("usage: receiver.py [snapshot]")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
