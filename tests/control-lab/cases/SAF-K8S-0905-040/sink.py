"""Case-owned persistent receiver for Fluent Bit's JSON Lines requests."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path

STORE = Path("/sink/events.jsonl")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/events":
            self.send_error(404)
            return
        payload = STORE.read_bytes() if STORE.exists() else b""
        self.send_response(200)
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if self.path not in {"/audit", "/access"}:
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 1048576:
            self.send_error(413)
            return
        try:
            events = [json.loads(line) for line in self.rfile.read(length).splitlines()]
            if not events or not all(isinstance(event, dict) for event in events):
                raise ValueError("expected event records")
        except (UnicodeDecodeError, ValueError):
            self.send_error(400)
            return
        with STORE.open("a", encoding="utf-8") as output:
            for event in events:
                output.write(json.dumps({"stream": self.path[1:], "event": event}) + "\n")
            output.flush()
            os.fsync(output.fileno())
        self.send_response(201)
        self.end_headers()


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
