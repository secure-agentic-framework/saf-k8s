"""Case-owned, strict mTLS receiver and bounded source/observer client."""
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
from pathlib import Path
import socket
import ssl
import sys
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

SERVER_CERT = "/credential/tls.crt"
SERVER_KEY = "/credential/tls.key"
CA_FILE = "/trust/ca.crt"
IDENTITIES_FILE = "/fixture/identities.json"
EVENTS_FILE = "/input/events.json"
HUB_TOKEN = "/hub-api/token"
HUB_CA = "/hub-api/ca.crt"
SERVER_NAME = "fixture-audit-collector.saf-test.svc"
EVENT_KEYS = {"source", "source_uid", "audit_id", "timestamp", "verb", "resource",
              "object", "actor", "status"}
MAX_BODY = 8192


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.sources = {}
        self.persisted = False

    def snapshot(self):
        with self.lock:
            return [self.sources[key]["summary"] for key in sorted(self.sources)]

    def accept(self, uri, source, events):
        with self.lock:
            if source["source_uid"] in self.sources:
                return False
            self.sources[source["source_uid"]] = {"summary": source, "events": events}
            return True

    def all_events(self):
        with self.lock:
            sources = sorted(self.sources.values(), key=lambda row: row["summary"]["source"])
            return [event for source in sources for event in source["events"]]


STATE = State()


def peer_uri(sock):
    try:
        sans = sock.getpeercert().get("subjectAltName", ())
        values = [value for kind, value in sans if kind == "URI"]
        return values[0] if len(values) == 1 else None
    except (AttributeError, ValueError):
        return None


def valid_event(event, expected_source, expected_uid):
    if not isinstance(event, dict) or set(event) != EVENT_KEYS:
        return False
    if (event.get("source") != expected_source or event.get("source_uid") != expected_uid
            or event.get("actor") != f"system:serviceaccount:saf-test:fixture-orchestration-actor"
            or not isinstance(event.get("audit_id"), str) or not event["audit_id"]
            or not isinstance(event.get("timestamp"), str)
            or not isinstance(event.get("status"), int)):
        return False
    return ((event.get("verb"), event.get("resource"), event.get("object"), event.get("status"))
            in {("patch", "configmaps", "fixture-cross-cluster-placement", 200),
                ("create", "deployments", "fixture-cross-cluster-workload", 201)})


class Receiver(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def reply(self, status, value):
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def identities(self):
        return json.loads(Path(IDENTITIES_FILE).read_text())

    def do_POST(self):
        identities = self.identities()
        uri = peer_uri(self.connection)
        principal = identities.get("sources", {}).get(uri)
        if self.path != "/events" or principal is None:
            return self.reply(403, {"accepted": False, "decision": "source-refused"})
        raw_length = self.headers.get("Content-Length", "")
        if not raw_length.isdecimal() or not 0 < int(raw_length) <= MAX_BODY:
            return self.reply(413, {"accepted": False, "decision": "bounded-body-required"})
        raw = self.rfile.read(int(raw_length))
        if len(raw) != int(raw_length):
            return self.reply(400, {"accepted": False, "decision": "incomplete-body"})
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self.reply(400, {"accepted": False, "decision": "invalid-json"})
        events = payload.get("events") if isinstance(payload, dict) else None
        if (not isinstance(payload, dict) or set(payload) != {"source_uid", "events"}
                or payload.get("source_uid") != principal["uid"]
                or not isinstance(events, list) or len(events) != 2
                or not all(valid_event(event, principal["source"], principal["uid"]) for event in events)
                or len({event["audit_id"] for event in events}) != 2
                or {(event["verb"], event["resource"], event["object"], event["status"])
                    for event in events} != {
                    ("patch", "configmaps", "fixture-cross-cluster-placement", 200),
                    ("create", "deployments", "fixture-cross-cluster-workload", 201),
                }):
            return self.reply(422, {"accepted": False, "decision": "event-binding-refused"})
        summary = {"source": principal["source"], "source_uid": principal["uid"],
                   "event_count": len(events),
                   "audit_ids": sorted(event["audit_id"] for event in events),
                   "event_batch_sha256": hashlib.sha256(raw).hexdigest()}
        if not STATE.accept(uri, summary, events):
            return self.reply(409, {"accepted": False, "decision": "duplicate-source-refused"})
        store_status = None
        if len(STATE.snapshot()) == 2 and not STATE.persisted:
            store_status = persist_central(STATE.all_events())
            if store_status != 201:
                return self.reply(503, {"accepted": False, "decision": "central-store-write-failed"})
            STATE.persisted = True
        return self.reply(202, {"accepted": True, "event_count": len(events),
                                "central_store_status": store_status})

    def do_GET(self):
        uri = peer_uri(self.connection)
        if self.path != "/state" or uri != self.identities().get("observer_uri"):
            return self.reply(403, {"accepted": False, "decision": "observer-refused"})
        sources = STATE.snapshot()
        enrolled = {item["source"] for item in self.identities()["sources"].values()}
        missing = enrolled - {item["source"] for item in sources}
        return self.reply(200, {"sources": sources, "missing_sources": sorted(missing)})


def serve():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    context.load_cert_chain(SERVER_CERT, SERVER_KEY)
    context.load_verify_locations(CA_FILE)
    context.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Receiver)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def persist_central(events):
    value = {"apiVersion": "v1", "kind": "ConfigMap",
             "metadata": {"name": "fixture-central-audit-records", "namespace": "saf-test"},
             "immutable": True,
             "data": {"events.json": json.dumps(events, sort_keys=True)}}
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    request = Request(
        "https://kubernetes.default.svc/api/v1/namespaces/saf-test/configmaps",
        data=body, method="POST", headers={
            "Authorization": "Bearer " + Path(HUB_TOKEN).read_text().strip(),
            "Content-Type": "application/json",
        })
    try:
        with urlopen(request, timeout=8, context=ssl.create_default_context(cafile=HUB_CA)) as response:
            response.read(2048)
            return response.status
    except HTTPError as error:
        error.read(2048)
        return error.code


def request(host, port, method, path, cert, key, payload=None):
    context = ssl.create_default_context(cafile=CA_FILE)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    context.load_cert_chain(cert, key)

    class Routed(HTTPSConnection):
        def connect(self):
            raw = socket.create_connection((self.host, self.port), timeout=5)
            self.sock = context.wrap_socket(raw, server_hostname=SERVER_NAME)

    conn = Routed(host, int(port), timeout=6)
    body = None if payload is None else json.dumps(payload, sort_keys=True,
                                                   separators=(",", ":")).encode()
    try:
        conn.request(method, path, body=body, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        result = json.loads(response.read(16384))
        return response.status, result
    finally:
        conn.close()


def send(host, port, negative=False):
    events = json.loads(Path(EVENTS_FILE).read_text())
    if not isinstance(events, list) or len(events) != 2:
        raise ValueError("The source did not stage both owned fixture events")
    payload = {"source_uid": events[0]["source_uid"], "events": events}
    cert = "/credential/wrong.crt" if negative else "/credential/tls.crt"
    key = "/credential/wrong.key" if negative else "/credential/tls.key"
    status, result = request(host, port, "POST", "/events", cert, key, payload)
    print(json.dumps({"status": status, **result}, sort_keys=True))


def observe(host, port):
    status, result = request(host, port, "GET", "/state", "/credential/tls.crt",
                             "/credential/tls.key")
    print(json.dumps({"status": status, **result}, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "serve":
        serve()
    elif len(sys.argv) == 4 and sys.argv[1] in {"send", "reject"}:
        send(sys.argv[2], sys.argv[3], negative=sys.argv[1] == "reject")
    elif len(sys.argv) == 4 and sys.argv[1] == "observe":
        observe(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit("invalid fixture mode")
