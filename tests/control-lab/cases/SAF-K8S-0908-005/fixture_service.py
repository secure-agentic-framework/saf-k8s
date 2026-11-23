"""Local-only model request fixture with a separate HTTP alert receiver.

The records are fixed by this file's client command. No submitted text is logged.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import URLError
from urllib.request import Request, urlopen


PORTS = {"baseline": 8080, "enforced": 8081, "alert-sink": 8082}
SERVICE_PORTS = {"fixture-model-baseline": 8080, "fixture-model-enforced": 8081}
ALERT_TARGET = "http://fixture-alert.saf-test.svc:8082/alerts"
RULE_ID = "fixture.marker.review.v1"

RECORDS = {
    "normal": {
        "request_id": "req-normal-001",
        "principal": "fixture:principal:reviewer",
        "model_id": "fixture-model-v1",
        "marker": "none",
        "features": {"signal": 0.25, "context": 0.75},
    },
    "selected": {
        "request_id": "req-marker-001",
        "principal": "fixture:principal:reviewer",
        "model_id": "fixture-model-v1",
        "marker": "review",
        "features": {"signal": 0.5, "context": 0.5},
    },
}
REQUEST_KEYS = {"request_id", "principal", "model_id", "marker", "features"}


def emit(event):
    print(json.dumps(event, sort_keys=True, separators=(",", ":")), flush=True)


def valid_record(record):
    return (
        isinstance(record, dict)
        and set(record) == REQUEST_KEYS
        and all(isinstance(record[key], str) and record[key] for key in
                ("request_id", "principal", "model_id", "marker"))
        and isinstance(record["features"], dict)
        and set(record["features"]) == {"signal", "context"}
        and all(type(value) in (int, float) and 0 <= value <= 1
                for value in record["features"].values())
    )


class Handler(BaseHTTPRequestHandler):
    role = ""

    def log_message(self, _format, *_args):
        # BaseHTTPRequestHandler's default access log includes client details.
        return

    def reply(self, status, payload):
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.reply(200, {"status": "ready"})
        else:
            self.reply(404, {"status": "not-found"})

    def do_POST(self):
        if self.role == "alert-sink" and self.path == "/alerts":
            self.receive_alert()
        elif self.role in ("baseline", "enforced") and self.path == "/predict":
            self.predict()
        else:
            self.reply(404, {"status": "not-found"})

    def read_json(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 2048:
                return None
            return json.loads(self.rfile.read(size))
        except (ValueError, TypeError, json.JSONDecodeError):
            return None

    def receive_alert(self):
        event = self.read_json()
        expected = {"event", "alert_id", "rule_id", "request_id", "principal", "model_id", "marker"}
        if (not isinstance(event, dict) or set(event) != expected
                or event.get("event") != "model-marker-detected"
                or any(not isinstance(event.get(key), str) or not event[key]
                       for key in expected)):
            self.reply(400, {"status": "invalid-alert"})
            return
        # Keep only the alert envelope: never log feature values or request bodies.
        emit({key: event[key] for key in sorted(expected)})
        self.reply(202, {"status": "received", "alert_id": event["alert_id"]})

    def predict(self):
        record = self.read_json()
        if not valid_record(record):
            self.reply(400, {"status": "invalid-request"})
            return
        if self.role == "enforced" and record["marker"] == "review":
            alert = {
                "event": "model-marker-detected",
                "alert_id": "alert-req-marker-001",
                "rule_id": RULE_ID,
                "request_id": record["request_id"],
                "principal": record["principal"],
                "model_id": record["model_id"],
                "marker": "review",
            }
            try:
                body = json.dumps(alert, sort_keys=True, separators=(",", ":")).encode()
                request = Request(ALERT_TARGET, data=body, headers={"Content-Type": "application/json"})
                with urlopen(request, timeout=3) as response:
                    delivered = response.status == 202
            except (URLError, TimeoutError, OSError):
                delivered = False
            if not delivered:
                self.reply(503, {"status": "alert-delivery-failed"})
                return
        # Synthetic inference response; no model or sensitive data is present.
        self.reply(200, {"status": "ok", "model_id": record["model_id"], "label": "fixture-class-a"})


def serve(role):
    Handler.role = role
    port = PORTS[role]
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()


def probe(service, record_name):
    record = RECORDS[record_name]
    body = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    request = Request(f"http://{service}.saf-test.svc:{SERVICE_PORTS[service]}/predict",
                      data=body, headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=5) as response:
            status, payload = response.status, json.loads(response.read())
    except URLError as error:
        status, payload = getattr(error, "code", 599), {}
    # Output excludes features and raw request data.
    print(json.dumps({"status": status, "response": payload}, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "serve":
        serve(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == "probe":
        probe(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit("usage: fixture_service.py serve ROLE | probe SERVICE RECORD")
