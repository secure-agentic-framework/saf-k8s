"""Normalize and classify only case-owned registry events."""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import json
from pathlib import Path
import ssl
from urllib.request import Request, urlopen

STORE = Path("/state/audit-events.json")
SOURCE = "fixture-forwarded-normalized-audit"
ACTIONS = {"PUT": "publish", "GET": "pull", "DELETE": "delete",
           "PATCH": "permission-change", "POST": "administration"}
SENSITIVE = {"publish", "delete", "permission-change", "administration"}
ALERT_RECEIVER = "https://audit-alert-receiver.saf-test.svc.cluster.local:8443/alerts"
RECEIVER_USER = Path("/receiver-auth/username").read_text().strip()
RECEIVER_PASSWORD = Path("/receiver-auth/password").read_text().strip()
RECEIVER_AUTH = base64.b64encode(f"{RECEIVER_USER}:{RECEIVER_PASSWORD}".encode()).decode()
RECEIVER_TLS = ssl.create_default_context(cafile="/receiver-ca/ca.pem")


def deliver_alert(alert):
    body = json.dumps(alert, sort_keys=True, separators=(",", ":")).encode()
    request = Request(ALERT_RECEIVER, data=body,
                      headers={"Content-Type": "application/json",
                               "Authorization": "Basic " + RECEIVER_AUTH}, method="POST")
    try:
        with urlopen(request, context=RECEIVER_TLS, timeout=3) as response:
            if response.status not in (200, 201):
                raise RuntimeError("alert receiver refused fixture alert")
    except Exception as exc:
        raise RuntimeError("case-owned alert route unavailable") from exc


def summarize(state):
    encoded = json.dumps(state["events"], sort_keys=True, separators=(",", ":")).encode()
    return {"events": sorted(state["events"]), "input_sha256": hashlib.sha256(encoded).hexdigest(),
            "alerts": state["alerts"], "quiet": sorted(state["quiet"]),
            "duplicates": state["duplicates"]}


def alert_rule(event):
    if not event["repository"].startswith("saf-test/"):
        return None
    action = event["normalized_action"]
    if action in SENSITIVE:
        return "sensitive-" + action
    if action == "pull" and event["classification"] == "fixture-anomalous":
        return "anomalous-pull"
    return None


def apply_batch(state, events, *, enforce):
    for event in events:
        identity = event["event_id"]
        previous = state["events"].get(identity)
        if previous is not None:
            if previous != event:
                raise ValueError("event ID already belongs to another record")
            state["duplicates"] += 1
            continue
        state["events"][identity] = event
        rule = alert_rule(event) if enforce else None
        if rule is None:
            state["quiet"].append(identity)
        else:
            alert_id = "alert-" + identity
            alert = {"alert_id": alert_id, "event_id": identity, "rule": rule,
                     "actor": event["actor"], "repository": event["repository"]}
            deliver_alert(alert)
            state["alerts"][alert_id] = {"event_id": identity, "rule": rule,
                                         "actor": event["actor"], "repository": event["repository"]}


def valid_event(event):
    fields = ("event_id", "source", "provider", "provider_action",
              "normalized_action", "repository", "actor", "classification")
    source_provider_pairs = {(SOURCE, "zot-fixture"),
                             ("zot-native-audit", "zot-v2.1.23")}
    return (isinstance(event, dict) and all(isinstance(event.get(key), str) and event[key] for key in fields)
            and (event["source"], event["provider"]) in source_provider_pairs
            and ACTIONS.get(event["provider_action"]) == event["normalized_action"])


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def reply(self, status, value):
        body = json.dumps(value, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self.reply(200, {"ready": True})
        self.reply(404, {"error": "unknown-route"})

    def do_POST(self):
        if self.path != "/ingest":
            return self.reply(404, {"error": "unknown-route"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 32768:
                return self.reply(413, {"error": "body-size"})
            request = json.loads(self.rfile.read(size))
            phase, events = request["phase"], request["events"]
        except (TypeError, KeyError, ValueError):
            return self.reply(400, {"error": "malformed-batch"})
        if phase not in {"baseline", "enforce"} or not isinstance(events, list):
            return self.reply(400, {"error": "invalid-batch"})
        if not events or not all(valid_event(event) for event in events):
            return self.reply(422, {"error": "invalid-event-provenance"})

        state = json.loads(STORE.read_text()) if STORE.exists() else {}
        current = state.setdefault(phase, {"events": {}, "alerts": {}, "quiet": [], "duplicates": 0})
        try:
            apply_batch(current, events, enforce=phase == "enforce")
        except ValueError:
            return self.reply(409, {"error": "event-id-conflict"})
        except RuntimeError:
            return self.reply(503, {"error": "case-alert-route-unavailable"})
        temp = STORE.with_suffix(".tmp")
        temp.write_text(json.dumps(state, sort_keys=True))
        temp.replace(STORE)
        self.reply(201, summarize(current))


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
