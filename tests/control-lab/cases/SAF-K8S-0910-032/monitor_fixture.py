"""Harmless cross-cluster telemetry collector and independent observer client."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import http.client
import json
import socket
import ssl
import sys
import threading
import time

SOURCE_URI = "spiffe://saf.test/ns/saf-test/sa/fixture-telemetry-source"
OBSERVER_URI = "spiffe://saf.test/ns/saf-test/sa/fixture-telemetry-observer"
UNAPPROVED_SOURCE_URI = "spiffe://saf.test/ns/saf-test/sa/fixture-telemetry-unapproved"
WINDOW_SECONDS = 20
MAX_RECORDS = 16
MAX_BODY_BYTES = 1024
RECORD_THRESHOLD = 3
BYTE_THRESHOLD = 1024


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.records = []
        self.events = []
        self.alerted = False

    def snapshot(self):
        with self.lock:
            now = time.monotonic()
            live = [row for row in self.records if now - row["received_at"] <= WINDOW_SECONDS]
            count = len({row["record_id"] for row in live})
            size = sum(row["body_bytes"] for row in live)
            return {
                "window_seconds": WINDOW_SECONDS,
                "record_count": count,
                "observed_bytes": size,
                "records": [{k: v for k, v in row.items() if k != "received_at"} for row in live],
                "events": list(self.events),
                "window_expired": bool(self.records) and not live,
            }

    def observe(self, row, alerting):
        with self.lock:
            now = time.monotonic()
            self.records[:] = [item for item in self.records if now - item["received_at"] <= WINDOW_SECONDS]
            if any(record["record_id"] == row["record_id"] for record in self.records):
                return False
            self.records.append({**row, "received_at": now})
            self.records[:] = self.records[-MAX_RECORDS:]
            live = self.records
            count = len({item["record_id"] for item in live})
            size = sum(item["body_bytes"] for item in live)
            if alerting and not self.alerted and (count > RECORD_THRESHOLD or size > BYTE_THRESHOLD):
                self.events.append({
                    "event": "telemetry-volume-threshold",
                    "source": SOURCE_URI,
                    "window_seconds": WINDOW_SECONDS,
                    "record_count": count,
                    "observed_bytes": size,
                    "thresholds": {"records_gt": RECORD_THRESHOLD, "bytes_gt": BYTE_THRESHOLD},
                })
                self.alerted = True
            return True


STATE = State()


def peer_uri(connection):
    sans = connection.getpeercert().get("subjectAltName", ())
    uris = [value for kind, value in sans if kind == "URI"]
    return uris[0] if len(uris) == 1 else None


class Collector(BaseHTTPRequestHandler):
    server_version = "FixtureCollector/1"

    def log_message(self, *_args):
        return

    def reply(self, status, value):
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        who = peer_uri(self.connection)
        if self.path == "/telemetry":
            if who != SOURCE_URI:
                return self.reply(403, {"decision": "source-refused"})
            raw_size = self.headers.get("Content-Length", "")
            if not raw_size.isdecimal() or int(raw_size) > MAX_BODY_BYTES:
                return self.reply(413, {"decision": "record-too-large"})
            raw = self.rfile.read(int(raw_size))
            if len(raw) != int(raw_size):
                return self.reply(400, {"decision": "incomplete-record"})
            try:
                record = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return self.reply(400, {"decision": "invalid-json"})
            if (not isinstance(record, dict) or set(record) != {"id", "metric", "synthetic"}
                    or record.get("synthetic") is not True
                    or not isinstance(record.get("id"), str)
                    or not record["id"].startswith("synthetic-telemetry-")
                    or not isinstance(record.get("metric"), int)
                    or not 0 <= record["metric"] <= 100):
                return self.reply(400, {"decision": "non-fixture-record-refused"})
            observed = {
                "source": who,
                "record_id": record["id"],
                "body_bytes": len(raw),
                "body_sha256": hashlib.sha256(raw).hexdigest(),
            }
            if not STATE.observe(observed, self.server.alerting):
                return self.reply(409, {"decision": "duplicate-record-refused"})
            return self.reply(202, {"decision": "observed", "record_id": record["id"]})
        return self.reply(404 if who == OBSERVER_URI else 403, {"decision": "observer-route-refused"})

    def do_GET(self):
        if self.path != "/fixture/report" or peer_uri(self.connection) != OBSERVER_URI:
            return self.reply(403, {"decision": "observer-route-refused"})
        return self.reply(200, STATE.snapshot())


def serve(alerting):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/credential/tls.crt", "/credential/tls.key")
    context.load_verify_locations("/trust/ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Collector)
    server.alerting = alerting
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def connection(host, port, server_name):
    context = ssl.create_default_context(cafile="/trust/ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/credential/tls.crt", "/credential/tls.key")
    class RoutedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection((self.host, self.port), timeout=self.timeout,
                                           source_address=self.source_address)
            self.sock = context.wrap_socket(raw, server_hostname=server_name)
    return RoutedHTTPSConnection(host, port, context=context, timeout=5)


def call(host, port, server_name, method, path, body=None):
    conn = connection(host, port, server_name)
    try:
        encoded = None if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        conn.request(method, path, body=encoded, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        payload = json.loads(response.read())
        return response.status, payload
    finally:
        conn.close()


def send(host, port, server_name, record_ids):
    results = []
    for record_id in record_ids:
        record = {"id": record_id, "metric": 7, "synthetic": True}
        status, reply = call(host, port, server_name, "POST", "/telemetry", record)
        results.append({"status": status, **reply})
    print(json.dumps({"sent": results}, sort_keys=True))



def probe_destination(host, port, expected_server_name, unapproved_server_name):
    """Return only a classification; suppress certificate/connection details."""
    record = {"id": "synthetic-telemetry-destination-probe", "metric": 7, "synthetic": True}
    try:
        status, _ = call(host, port, unapproved_server_name, "POST", "/telemetry", record)
        result = {"destination_identity_rejected": False, "unexpected_http_status": status}
    except ssl.SSLCertVerificationError:
        result = {"destination_identity_rejected": True, "classification": "certificate_identity_mismatch"}
    except (ConnectionRefusedError, TimeoutError, socket.timeout):
        result = {"destination_identity_rejected": False, "classification": "transport_unavailable"}
    print(json.dumps({"configured_destination": expected_server_name, **result}, sort_keys=True))


def observe(host, port, server_name, expected_state, expected_ids):
    status, report = call(host, port, server_name, "GET", "/fixture/report")
    expected = []
    for record_id in expected_ids:
        body = json.dumps({"id": record_id, "metric": 7, "synthetic": True},
                          sort_keys=True, separators=(",", ":")).encode()
        expected.append({"source": SOURCE_URI, "record_id": record_id,
                         "body_bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest()})
    actual = sorted(report.get("records", []), key=lambda row: row.get("record_id", ""))
    expected.sort(key=lambda row: row["record_id"])
    events = report.get("events", [])
    if expected_state == "quiet":
        alert_match = events == []
    else:
        want_count = len(expected)
        want_bytes = sum(row["body_bytes"] for row in expected)
        alert_match = events == [{
            "event": "telemetry-volume-threshold", "source": SOURCE_URI,
            "window_seconds": WINDOW_SECONDS, "record_count": want_count,
            "observed_bytes": want_bytes,
            "thresholds": {"records_gt": RECORD_THRESHOLD, "bytes_gt": BYTE_THRESHOLD},
        }]
    checks = {
        "collector_report_received": status == 200,
        "records_match_expected_source_and_observed_content": actual == expected,
        "measured_count_matches_observed_identifiable_records": report.get("record_count") == len(expected),
        "measured_bytes_match_observed_payload_bytes": report.get("observed_bytes") == sum(
            row["body_bytes"] for row in expected),
        "bounded_window_has_not_expired": report.get("window_expired") is False,
        "alert_state_matches_phase": alert_match,
    }
    print(json.dumps({"checks": checks, "report": report}, sort_keys=True))


if __name__ == "__main__":
    operation, *args = sys.argv[1:]
    if operation == "serve":
        serve(args[0] == "enabled")
    else:
        host, port, server_name, *rest = args
        if operation == "send":
            send(host, int(port), server_name, rest)
        elif operation == "observe":
            observe(host, int(port), server_name, rest[0], rest[1:])
        elif operation == "destination-probe":
            if len(rest) != 1:
                raise SystemExit("destination-probe requires one unapproved server name")
            probe_destination(host, int(port), server_name, rest[0])
        elif operation == "health":
            try:
                status, _ = call(host, int(port), server_name, "GET", "/fixture/report")
                ready = status == 200
            except (ConnectionRefusedError, TimeoutError):
                ready = False
            print(json.dumps({"ready": ready}))
        else:
            raise SystemExit("Unknown fixture operation")
