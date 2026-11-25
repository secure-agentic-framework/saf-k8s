"""Isolated synthetic budget policy with scale-subresource-only RBAC."""
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.request


NAMESPACE = os.environ["POD_NAMESPACE"]
WORKLOAD = "synthetic-inference"
CAP = Decimal("10.00")
UNIT_COST = Decimal("5.00")
TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
API = "https://kubernetes.default.svc"
SERVICE_DEGRADED = False
ALLOWED_INFERENCE_IDS = {"saf-0903-008-normal-001", "saf-0903-008-over-cap-001",
                        "saf-0903-008-recovery-001"}


def api(method, path, body=None):
    token = TOKEN_PATH.read_text().strip()
    raw = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(API + path, data=raw, method=method,
                                     headers={"Authorization": "Bearer " + token,
                                              "Content-Type": "application/merge-patch+json"})
    context = ssl.create_default_context(cafile=CA_PATH)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    with opener.open(request, timeout=10) as response:
        return json.loads(response.read())


def evaluate(data):
    global SERVICE_DEGRADED
    if set(data) != {"demand_replicas", "budget_enabled"}:
        raise ValueError("expected only demand_replicas and budget_enabled")
    demand = data["demand_replicas"]
    enabled = data["budget_enabled"]
    if type(demand) is not int or demand not in (1, 2, 3) or type(enabled) is not bool:
        raise ValueError("demand must be an integer from 1 to 3 and budget_enabled a boolean")

    cost = (UNIT_COST * demand).quantize(Decimal("0.01"))
    scale_path = f"/apis/apps/v1/namespaces/{NAMESPACE}/deployments/{WORKLOAD}/scale"
    current = api("GET", scale_path)["spec"]["replicas"]
    over_cap = enabled and cost > CAP
    SERVICE_DEGRADED = over_cap
    target = min(current, demand) if over_cap else demand
    if target != current:
        api("PATCH", scale_path, {"spec": {"replicas": target}})
    return {"demand_replicas": demand, "unit_cost": str(UNIT_COST),
            "projected_spend": str(cost), "approved_cap": str(CAP),
            "budget_enabled": enabled, "allowed": not over_cap,
            "requested_replicas": target, "degraded_service": over_cap,
            "decision": "suppress_scale_up_and_degrade" if over_cap else "allow"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def respond(self, status, value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/-/ready":
            self.respond(200, {"ready": True})
        else:
            self.respond(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/inference":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 128:
                    self.respond(400, {"error": "invalid fixture envelope"})
                    return
                data = json.loads(self.rfile.read(length))
                request_id = data.get("request_id") if isinstance(data, dict) else None
                if set(data) != {"request_id"} or request_id not in ALLOWED_INFERENCE_IDS:
                    self.respond(400, {"error": "unknown fixed fixture request"})
                    return
                if SERVICE_DEGRADED:
                    self.respond(429, {"accepted": False, "decision": "budget_throttle",
                                       "request_id": request_id})
                else:
                    self.respond(200, {"accepted": True, "decision": "served_fixture_response",
                                       "request_id": request_id,
                                       "result": "SYNTHETIC_SAFE_RESPONSE"})
            except Exception as error:
                self.respond(400, {"error": type(error).__name__})
            return
        if self.path != "/evaluate":
            self.respond(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 512:
                self.respond(400, {"error": "invalid fixture envelope"})
                return
            data = json.loads(self.rfile.read(length))
            decision = evaluate(data)
            self.respond(429 if decision["degraded_service"] else 200, decision)
        except (ValueError, KeyError, TypeError) as error:
            self.respond(400, {"error": str(error)})
        except urllib.error.HTTPError as error:
            self.respond(502, {"error": f"Kubernetes API returned HTTP {error.code}"})
        except Exception as error:
            self.respond(502, {"error": type(error).__name__})


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
