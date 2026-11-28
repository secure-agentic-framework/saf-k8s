"""Local-only exporter and bounded Alertmanager receiver for Hopper fixtures."""
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock


RECEIPT = Path("/fixture/receipt.json")
BASELINE = Path("/scratch/baseline")
APPROVED_BASELINE = Path("/fixture/approved-baseline")
HEX256 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED = {
    "schema": "saf-nvidia-hopper-archived-spdm-v1",
    "reference_evaluation_at_utc": "2026-11-23T00:00:00Z",
    "device_root_sha256": "102bf659d5419614c9d8e6aecebc80454eb26b1df6a769ac720b9a690b167b48",
    "transcript_sha256": "daf8ea2aa9adeb64d3e95fdb1adc1e7d35f27224562fb176cc04895f864b6f8c",
    "measurement_record_sha256": "ccd646a0ba2f2fbdb91efaf5d666147b11f0012cc3021ef0d21dca00be8ede78",
    "measurement_count": 64,
    "driver_version": "580.159.03",
    "certificate_revocation_evaluated": False,
    "live_device_or_freshness_observed": False,
    "archived_device_chain_and_signature_verified": True,
    "signed_report_fields_match_pinned_reference": True,
    "signed_reference_manifests_verified": True,
    "driver_rim_active_measurements_matched": 22,
    "vbios_rim_active_measurements_matched": 12,
    "changed_measurement_signature_denied": True,
    "embedded_root_without_trust_denied": True,
    "pre_validity_chain_denied": True,
    "altered_driver_rim_denied": True,
    "altered_vbios_rim_denied": True,
    "altered_measurement_values_fail_reference_comparison": True,
}
MAX_BODY = 8192
MAX_ALERTS = 8
MAX_EVENTS = 64
events = []
events_lock = Lock()
receipt = None


class InvalidBaseline(Exception):
    pass


def load_receipt():
    try:
        raw = RECEIPT.read_bytes()
        if len(raw) > 32768:
            raise ValueError
        doc = json.loads(raw, object_pairs_hook=unique_object)
    except (OSError, ValueError, TypeError):
        raise RuntimeError("invalid archived receipt") from None
    if not isinstance(doc, dict) or set(doc) != set(REQUIRED):
        raise RuntimeError("invalid archived receipt")
    for key, expected in REQUIRED.items():
        value = doc.get(key)
        if type(value) is not type(expected) or value != expected:
            raise RuntimeError("invalid archived receipt")
    for key in ("device_root_sha256", "transcript_sha256", "measurement_record_sha256"):
        if not isinstance(doc[key], str) or HEX256.fullmatch(doc[key]) is None:
            raise RuntimeError("invalid archived receipt")
    return doc


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def current_state():
    measurement = receipt["measurement_record_sha256"]
    try:
        try:
            raw = BASELINE.read_bytes()
        except FileNotFoundError:
            raw = APPROVED_BASELINE.read_bytes()
        baseline = raw.removesuffix(b"\n").decode("ascii")
    except (OSError, UnicodeError):
        raise InvalidBaseline from None
    if HEX256.fullmatch(baseline) is None:
        raise InvalidBaseline
    return {
        "measurement_sha256": measurement,
        "transcript_sha256": receipt["transcript_sha256"],
        "approval_match": baseline == measurement,
        "live_eligible": False,
        "baseline_sha256": baseline,
    }


def metric(name, value):
    return f"{name} {value}\n"


class Handler(BaseHTTPRequestHandler):
    def _reply(self, status, body, content_type="application/json"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            self._reply(200, b"ok\n", "text/plain; charset=utf-8")
            return
        if self.server.role == "exporter":
            if self.path not in ("/state", "/metrics"):
                self._reply(404, b"not found\n", "text/plain; charset=utf-8")
                return
            try:
                state = current_state()
            except InvalidBaseline:
                self._reply(503, b"service unavailable\n", "text/plain; charset=utf-8")
                return
            if self.path == "/state":
                self._reply(200, json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n")
                return
            metrics = "".join((
                metric("fixture_hopper_archive_approval_match", int(state["approval_match"])),
                metric("fixture_hopper_archive_verified", 1),
                metric("fixture_hopper_live_eligible", 0),
                metric("fixture_hopper_route_probe", 1),
            ))
            self._reply(200, metrics, "text/plain; version=0.0.4; charset=utf-8")
            return
        if self.path != "/events":
            self._reply(404, b"not found\n", "text/plain; charset=utf-8")
            return
        with events_lock:
            snapshot = list(events)
        self._reply(200, json.dumps(snapshot, sort_keys=True, separators=(",", ":")) + "\n")

    def do_POST(self):
        if self.server.role != "receiver" or self.path != "/events":
            self._reply(404, b"not found\n", "text/plain; charset=utf-8")
            return
        length_text = self.headers.get("Content-Length")
        if (length_text is None or len(length_text) > 10 or not length_text.isascii()
                or not length_text.isdecimal()):
            self._reply(400, b"bad request\n", "text/plain; charset=utf-8")
            return
        length = int(length_text)
        if length > MAX_BODY:
            self._reply(413, b"payload too large\n", "text/plain; charset=utf-8")
            return
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError
            payload = json.loads(raw, object_pairs_hook=unique_object)
            if not isinstance(payload, dict):
                raise ValueError
            receiver = payload.get("receiver")
            status = payload.get("status")
            alerts = payload.get("alerts")
            if (not isinstance(receiver, str) or not receiver or len(receiver) > 160 or
                    status not in ("firing", "resolved") or not isinstance(alerts, list) or
                    not alerts or len(alerts) > MAX_ALERTS):
                raise ValueError
            rows = []
            for alert in alerts:
                if not isinstance(alert, dict) or not isinstance(alert.get("labels"), dict):
                    raise ValueError
                alert_status = alert.get("status")
                labels = alert["labels"]
                name = labels.get("alertname")
                source = labels.get("evidence_source")
                if (alert_status not in ("firing", "resolved") or
                        not isinstance(name, str) or not name or len(name) > 160 or
                        not isinstance(source, str) or not source or len(source) > 160):
                    raise ValueError
                rows.append({"receiver": receiver, "name": name, "status": alert_status,
                             "evidence_source": source})
        except (ValueError, TypeError):
            self._reply(400, b"bad request\n", "text/plain; charset=utf-8")
            return
        with events_lock:
            if len(events) + len(rows) > MAX_EVENTS:
                self._reply(429, b"event capacity reached\n", "text/plain; charset=utf-8")
                return
            events.extend(rows)
        self._reply(200, b"{}\n")

    def log_message(self, _format, *_args):
        pass


def main():
    global receipt
    if len(sys.argv) != 2 or sys.argv[1] not in ("exporter", "receiver"):
        raise SystemExit("usage: hopper_monitor.py exporter|receiver")
    role = sys.argv[1]
    if role == "exporter":
        receipt = load_receipt()
        host, port = "0.0.0.0", 8080
    else:
        host, port = "0.0.0.0", 18082
    server = ThreadingHTTPServer((host, port), Handler)
    server.role = role
    server.serve_forever()


if __name__ == "__main__":
    main()
