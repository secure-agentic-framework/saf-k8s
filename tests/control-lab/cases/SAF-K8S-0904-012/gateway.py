"""Small bounded transfer gateway used only by the synthetic lab fixture."""
import hashlib
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

MAX_REQUEST = 1024
OPENER = build_opener(ProxyHandler({}))
DESTINATIONS = {"public": "pipeline-public-destination",
                "restricted": "pipeline-restricted-destination"}
MAX_MARKER_BYTES = 256
ALLOWED_FIELDS = {"request_ref", "event_id", "source_stage", "source_classification",
                  "destination_stage", "destination_classification", "marker", "marker_sha256"}


def load_json(path):
    return json.loads(Path(path).read_text())


def receipt(decision, reason, event):
    return {"decision": decision, "reason": reason,
            "request_ref": event["request_ref"], "event_id": event["event_id"]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def send_json(self, status, obj):
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"status": "ok"})
        else:
            self.send_json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/transfer":
            self.send_json(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 0 or length > MAX_REQUEST:
                self.send_json(413, {"error": "request_too_large"})
                return
            event = json.loads(self.rfile.read(length))
            if not isinstance(event, dict) or set(event) != ALLOWED_FIELDS:
                self.send_json(400, {"error": "invalid_typed_request"})
                return
            if any(not isinstance(value, str) or len(value) > 128 for value in event.values()):
                self.send_json(400, {"error": "invalid_field"})
                return
            scope = load_json("/scope/scope.json")
            policy = load_json("/policy/policy.json")
            if event == scope["ordinary"]:
                decision, reason = "allow", "same_classification"
            elif event != scope["cross_classification"]:
                self.send_json(403, receipt("deny", "stage_scope_mismatch", event))
                return
            elif not policy.get("enabled"):
                decision, reason = "allow", "policy_disabled"
            else:
                try:
                    approval = load_json("/approval/approval.json")
                except (FileNotFoundError, json.JSONDecodeError):
                    self.send_json(403, receipt("deny", "approval_required", event))
                    return
                if approval != event:
                    self.send_json(403, receipt("deny", "approval_scope_mismatch", event))
                    return
                decision, reason = "allow", "exact_approval"

            marker = Path("/fixture/marker.txt").read_bytes()
            if len(marker) > MAX_MARKER_BYTES or hashlib.sha256(marker).hexdigest() != event["marker_sha256"]:
                self.send_json(422, {"error": "marker_check_failed"})
                return
            forward = Request(
                f"http://{DESTINATIONS[event['destination_classification']]}:8081/receive",
                data=marker,
                headers={"Content-Type": "application/octet-stream",
                         "X-SAF-Event-ID": event["event_id"],
                         "X-SAF-Source-Stage": event["source_stage"],
                         "X-SAF-Source-Class": event["source_classification"],
                         "X-SAF-Destination-Stage": event["destination_stage"],
                         "X-SAF-Destination-Class": event["destination_classification"],
                         "X-SAF-Marker-SHA256": event["marker_sha256"]}, method="POST")
            try:
                with OPENER.open(forward, timeout=3) as response:
                    result = json.loads(response.read())
            except (HTTPError, URLError, TimeoutError) as error:
                self.send_json(502, {"error": "destination_unavailable"})
                return
            if result.get("accepted") is not True or result.get("sha256") != event["marker_sha256"]:
                self.send_json(502, {"error": "destination_receipt_mismatch"})
                return
            self.send_json(200, receipt(decision, reason, event))
        except (ValueError, TypeError, KeyError, OSError):
            self.send_json(400, {"error": "invalid_request"})


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
