"""Owned, fixed-input authenticated model-alert identity fixture.

Projected tokens are read only by the HTTPS request path or TokenReview client;
they are never printed, returned, or written to evidence.
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

NS = "saf-test"
CALLER_AUDIENCE = "saf-fixture-model-call"
ALERT_AUDIENCE = "saf-fixture-alerts"
APPROVED_CALLER = f"system:serviceaccount:{NS}:fixture-caller-approved"
MODEL_IDENTITY = f"system:serviceaccount:{NS}:fixture-model-identity"
ALERT_IDENTITY = f"system:serviceaccount:{NS}:fixture-alert-identity"
RULE_ID = "fixture.marker.review.auth.v1"
MODEL_ID = "fixture-model-auth-v1"
CALLER_TOKEN = "/caller/token"
ALERT_TOKEN = "/alert-token/token"
API_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
API_CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
TRUST_CA = "/trust/ca.crt"

NORMAL = {"request_id": "auth-req-normal-001", "model_id": MODEL_ID,
          "marker": "none", "features": {"signal": 0.25, "context": 0.75},
          "claimed_principal": "fixture:claimed:ordinary"}
SELECTED = {"request_id": "auth-req-marker-001", "model_id": MODEL_ID,
            "marker": "review", "features": {"signal": 0.5, "context": 0.5},
            "claimed_principal": "fixture:claimed:forged"}
ALERT_KEYS = {"event", "alert_id", "rule_id", "request_id", "principal", "model_id", "marker"}


def open_tls(request, ca, timeout):
    verification = HTTPSHandler(context=ssl.create_default_context(cafile=ca))
    return build_opener(ProxyHandler({}), verification).open(request, timeout=timeout)


def api_request(path, body):
    token = open(API_TOKEN, encoding="utf-8").read().strip()
    data = json.dumps(body, separators=(",", ":")).encode()
    request = Request("https://kubernetes.default.svc" + path, data=data,
                      headers={"Authorization": "Bearer " + token,
                               "Content-Type": "application/json"}, method="POST")
    with open_tls(request, API_CA, 4) as response:
        return json.loads(response.read())


def verified_user(token, audience):
    if not token:
        return None
    result = api_request("/apis/authentication.k8s.io/v1/tokenreviews", {
        "apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
        "spec": {"token": token, "audiences": [audience]},
    }).get("status", {})
    if not result.get("authenticated") or audience not in result.get("audiences", []):
        return None
    return result.get("user", {}).get("username")


def request_json(handler):
    try:
        size = int(handler.headers.get("Content-Length", "0"))
        if not 0 < size <= 2048:
            return None
        value = json.loads(handler.rfile.read(size))
        return value if isinstance(value, dict) else None
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def emit(value):
    # Only the minimized alert envelope is recorded. Never print request,
    # feature, authorization-header, or projected-token values.
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)


class Handler(BaseHTTPRequestHandler):
    role = ""
    accepted = []

    def log_message(self, *_args):
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
            return self.reply(200, {"status": "ready"})
        return self.reply(404, {"status": "not-found"})

    def do_POST(self):
        if self.role == "model" and self.path == "/predict":
            return self.predict()
        if self.role == "sink" and self.path == "/alerts":
            return self.receive_alert()
        return self.reply(404, {"status": "not-found"})

    def predict(self):
        authorization = self.headers.get("Authorization", "")
        token = authorization[7:] if authorization.startswith("Bearer ") else ""
        if not token:
            return self.reply(401, {"status": "unauthenticated"})
        try:
            principal = verified_user(token, CALLER_AUDIENCE)
        except (URLError, TimeoutError, OSError, ValueError):
            return self.reply(503, {"status": "identity-review-unavailable"})
        if not principal:
            return self.reply(401, {"status": "unauthenticated"})
        if principal != APPROVED_CALLER:
            return self.reply(403, {"status": "caller-not-approved"})
        record = request_json(self)
        required = {"request_id", "model_id", "marker", "features", "claimed_principal"}
        if (record is None or set(record) != required
                or record.get("model_id") != MODEL_ID
                or record.get("marker") not in ("none", "review")
                or not isinstance(record.get("request_id"), str)
                or not isinstance(record.get("claimed_principal"), str)
                or not isinstance(record.get("features"), dict)
                or set(record["features"]) != {"signal", "context"}
                or any(type(v) not in (int, float) or not 0 <= v <= 1
                       for v in record["features"].values())):
            return self.reply(400, {"status": "invalid-request"})
        if record["marker"] == "review":
            event = {"event": "model-marker-detected",
                     "alert_id": "alert-" + record["request_id"],
                     "rule_id": RULE_ID, "request_id": record["request_id"],
                     "principal": principal, "model_id": MODEL_ID, "marker": "review"}
            try:
                token = open(ALERT_TOKEN, encoding="utf-8").read().strip()
                body = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
                request = Request("https://fixture-auth-alert.saf-test.svc:8443/alerts", data=body,
                                  headers={"Authorization": "Bearer " + token,
                                           "Content-Type": "application/json"})
                with open_tls(request, TRUST_CA, 4) as response:
                    if response.status != 202:
                        return self.reply(503, {"status": "alert-delivery-failed"})
            except (URLError, TimeoutError, OSError, ValueError):
                return self.reply(503, {"status": "alert-delivery-failed"})
        return self.reply(200, {"status": "ok", "model_id": MODEL_ID})

    def receive_alert(self):
        authorization = self.headers.get("Authorization", "")
        token = authorization[7:] if authorization.startswith("Bearer ") else ""
        if not token:
            return self.reply(401, {"status": "unauthenticated-source"})
        try:
            source = verified_user(token, ALERT_AUDIENCE)
        except (URLError, TimeoutError, OSError, ValueError):
            return self.reply(503, {"status": "source-review-unavailable"})
        if not source:
            return self.reply(401, {"status": "unauthenticated-source"})
        if source != MODEL_IDENTITY:
            return self.reply(403, {"status": "source-not-approved"})
        event = request_json(self)
        if (event is None or set(event) != ALERT_KEYS
                or event.get("event") != "model-marker-detected"
                or event.get("rule_id") != RULE_ID
                or event.get("principal") != APPROVED_CALLER
                or event.get("model_id") != MODEL_ID
                or event.get("marker") != "review"):
            return self.reply(400, {"status": "invalid-alert"})
        self.accepted.append(event)
        emit(event)
        return self.reply(202, {"status": "received", "alert_id": event["alert_id"]})


def serve(role):
    Handler.role = role
    Handler.accepted = []
    server = HTTPServer(("0.0.0.0", 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/certificate/tls.crt", "/certificate/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def _https(url, payload, token=None):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = Request(url, data=body, headers=headers, method="POST")
    try:
        with open_tls(request, TRUST_CA, 6) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())
    except URLError:
        return 599, {"status": "unavailable"}


def probe_model(mode):
    record = dict(NORMAL if mode == "normal" else SELECTED)
    token = None
    try:
        token = open(CALLER_TOKEN, encoding="utf-8").read().strip()
    except FileNotFoundError:
        pass
    status, response = _https("https://fixture-auth-model.saf-test.svc:8443/predict", record, token)
    print(json.dumps({"status": status, "body": response}, sort_keys=True, separators=(",", ":")))


def probe_sink(mode):
    path = CALLER_TOKEN if mode == "wrong-audience" else ALERT_TOKEN
    token = open(path, encoding="utf-8").read().strip()
    event = {"event": "model-marker-detected", "alert_id": "alert-direct-comparator",
             "rule_id": RULE_ID, "request_id": "direct-comparator", "principal": APPROVED_CALLER,
             "model_id": MODEL_ID, "marker": "review"}
    status, response = _https("https://fixture-auth-alert.saf-test.svc:8443/alerts", event, token)
    print(json.dumps({"status": status, "body": response}, sort_keys=True, separators=(",", ":")))


def readiness():
    for target in ("fixture-auth-model", "fixture-auth-alert"):
        try:
            with open_tls(f"https://{target}.saf-test.svc:8443/health", TRUST_CA, 3) as response:
                if response.status != 200:
                    return False
        except (URLError, TimeoutError, OSError):
            return False
    return True


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "serve" and sys.argv[2] in {"model", "sink"}:
        serve(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "probe-model" and sys.argv[2] in {"selected", "normal"}:
        probe_model(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "probe-sink" and sys.argv[2] in {
        "wrong-audience", "wrong-source"
    }:
        probe_sink(sys.argv[2])
    elif sys.argv[1:] == ["ready"]:
        print("ready" if readiness() else "pending")
    else:
        raise SystemExit("usage: identity_fixture.py serve model|sink | probe-model selected|normal | probe-sink")
