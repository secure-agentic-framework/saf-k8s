"""Bounded local notification sink for inert case alerts only."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path

STORE = Path("/state/alerts.json")
FIELDS = {"alert_id", "event_id", "rule", "actor", "repository"}


def read_state():
    if STORE.exists():
        return json.loads(STORE.read_text())
    return {"alerts": {}, "duplicates": 0}


def save_state(state):
    tmp = STORE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")))
    tmp.replace(STORE)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        return

    def reply(self, status, value):
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self.reply(200, {"ready": True})
        if self.path != "/alerts":
            return self.reply(404, {"error": "unknown-route"})
        state = read_state()
        self.reply(200, {"alerts": [state["alerts"][key]
                                    for key in sorted(state["alerts"])],
                         "duplicates": state["duplicates"]})

    def do_POST(self):
        if self.path != "/alerts":
            return self.reply(404, {"error": "unknown-route"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 4096:
                return self.reply(413, {"error": "body-size"})
            value = json.loads(self.rfile.read(size))
        except (TypeError, ValueError):
            return self.reply(400, {"error": "malformed-alert"})
        if (not isinstance(value, dict) or set(value) != FIELDS
                or not all(isinstance(value[key], str) and value[key] for key in FIELDS)):
            return self.reply(422, {"error": "invalid-alert-shape"})

        state = read_state()
        prior = state["alerts"].get(value["alert_id"])
        if prior is not None:
            if prior != value:
                return self.reply(409, {"error": "alert-id-conflict"})
            state["duplicates"] += 1
            save_state(state)
            return self.reply(200, {"accepted": True, "duplicate": True})
        state["alerts"][value["alert_id"]] = value
        save_state(state)
        self.reply(201, {"accepted": True, "duplicate": False})


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
