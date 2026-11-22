"""Strict fixture-only MLflow dispatch gateway with an append-only audit sink."""
import base64
import hmac
import json
import os
from pathlib import Path
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode
from urllib.request import Request, urlopen

BACKEND = "http://localhost:5001"
MODE = Path("/mode/audit-mode")
AUDIT = Path("/audit/events.jsonl")
LOCK = threading.Lock()
# Fixture-only credentials. The bridge never writes them to a log or response.
ACTORS = {
    "lab-admin": ("fixture-admin-key-0904", {"administrative"}),
    "lab-reader": ("fixture-reader-key-0904", {"read"}),
    "lab-writer": ("fixture-writer-key-0904", {"write", "delete"}),
}


def backend(method, path, body=None):
    payload = None if body is None else json.dumps(body, sort_keys=True).encode()
    request = Request(BACKEND + path, data=payload, method=method,
                      headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=4) as response:
            raw = response.read()
            status = response.status
    except Exception:
        return 0, {}
    try:
        return status, json.loads(raw or b"{}")
    except (ValueError, TypeError):
        return status, {}


def audit(actor, operation, resource_id, status):
    if MODE.read_text().strip() != "on":
        return
    event = {"actor": actor, "operation": operation,
             "resource_id": str(resource_id),
             "result": "success" if 200 <= status < 300 else "failure"}
    with LOCK:
        with AUDIT.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
            stream.flush()
            os.fsync(stream.fileno())


class Handler(BaseHTTPRequestHandler):
    server_version = "FixtureAuditBridge/1"

    def log_message(self, _format, *_args):
        # Default BaseHTTPRequestHandler logs request metadata; the fixture is quiet.
        return

    def send_json(self, status, value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def actor(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return None
        try:
            decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:
            return None
        entry = ACTORS.get(username)
        if entry and hmac.compare_digest(password, entry[0]):
            return username
        return None

    def do_GET(self):
        if self.path == "/health":
            status, _ = backend("GET", "/version")
            self.send_json(200 if status == 200 else 503, {"ready": status == 200})
        else:
            self.send_json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/dispatch":
            self.send_json(404, {"error": "not_found"})
            return
        actor = self.actor()
        if actor is None:
            self.send_json(401, {"error": "unauthenticated"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 1024:
                raise ValueError
            data = json.loads(self.rfile.read(length))
            if set(data) - {"operation", "phase", "experiment_id", "run_id"}:
                raise ValueError
            phase = data.get("phase")
            if phase not in ("off", "on"):
                raise ValueError
            operation = data.get("operation")
        except Exception:
            self.send_json(400, {"error": "invalid_fixture_request"})
            return

        # Every operation below is a fixed MLflow REST API call. The request body
        # can select only one fixed operation and a server-issued resource ID.
        if operation == "create_experiment" and actor == "lab-admin":
            api_method, api_path, api_body = "POST", "/api/2.0/mlflow/experiments/create", {
                "name": "SAF-K8S-0904-016-" + phase,
                "tags": [{"key": "fixture", "value": "owned"}],
            }
            category, fallback_id = "administrative", "fixture-experiment"
        elif operation == "get_experiment" and actor == "lab-reader":
            experiment_id = data.get("experiment_id", "")
            if not experiment_id.isdecimal():
                self.send_json(400, {"error": "invalid_fixture_resource"})
                return
            api_method, api_path, api_body = "GET", "/api/2.0/mlflow/experiments/get?" + urlencode(
                {"experiment_id": experiment_id}), None
            category, fallback_id = "read", experiment_id
        elif operation == "create_run" and actor == "lab-writer":
            experiment_id = data.get("experiment_id", "")
            if not experiment_id.isdecimal():
                self.send_json(400, {"error": "invalid_fixture_resource"})
                return
            api_method, api_path, api_body = "POST", "/api/2.0/mlflow/runs/create", {
                "experiment_id": experiment_id, "start_time": 1,
                "run_name": "fixed-audit-witness",
                "tags": [{"key": "fixture", "value": "owned"}],
            }
            category, fallback_id = "write", experiment_id
        elif operation == "log_parameter" and actor == "lab-writer":
            run_id = data.get("run_id", "")
            if len(run_id) != 32 or any(c not in "0123456789abcdef" for c in run_id):
                self.send_json(400, {"error": "invalid_fixture_resource"})
                return
            api_method, api_path, api_body = "POST", "/api/2.0/mlflow/runs/log-parameter", {
                "run_id": run_id, "key": "fixture_parameter", "value": "fixed-value",
            }
            category, fallback_id = "write", run_id
        elif operation == "delete_run" and actor == "lab-writer":
            run_id = data.get("run_id", "")
            if len(run_id) != 32 or any(c not in "0123456789abcdef" for c in run_id):
                self.send_json(400, {"error": "invalid_fixture_resource"})
                return
            api_method, api_path, api_body = "POST", "/api/2.0/mlflow/runs/delete", {"run_id": run_id}
            category, fallback_id = "delete", run_id
        else:
            self.send_json(403, {"error": "operation_not_allowlisted"})
            return

        status, response = backend(api_method, api_path, api_body)
        resource_id = fallback_id
        if status == 200 and operation == "create_experiment":
            resource_id = response.get("experiment_id", fallback_id)
        elif status == 200 and operation == "create_run":
            resource_id = response.get("run", {}).get("info", {}).get("run_id", fallback_id)
        audit(actor, category, resource_id, status)
        if status != 200:
            self.send_json(502, {"error": "tracking_api_failed"})
            return
        # Keep output small and omit all request and credential material.
        if operation == "create_experiment":
            result = {"ok": True, "resource_id": str(resource_id)}
        elif operation == "create_run":
            result = {"ok": True, "resource_id": str(resource_id)}
        else:
            result = {"ok": True, "resource_id": str(resource_id)}
        self.send_json(200, result)


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
