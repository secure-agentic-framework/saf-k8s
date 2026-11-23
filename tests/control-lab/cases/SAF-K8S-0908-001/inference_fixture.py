"""A fixed synthetic predictor and a scoped authenticated request quota."""
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import math
from pathlib import Path
import ssl
import sys
import time
from urllib.request import ProxyHandler, Request, build_opener, HTTPSHandler

AUDIENCE = "saf-scoped-inference"
NS = "saf-test"
API = Path("/var/run/secrets/kubernetes.io/serviceaccount")
PREDICTOR = "http://fixture-synthetic-predictor.saf-test.svc:8080/predict"
RESULT = "synthetic-label"
ALLOWED_SUBJECTS = {f"system:serviceaccount:{NS}:fixture-inference-{label}" for label in ("alpha", "beta")}
LIMIT = 2
WINDOW = 20


def identify(credential):
    query = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
             "spec": {"token": credential, "audiences": [AUDIENCE]}}
    endpoint = "https://kubernetes.default.svc/apis/authentication.k8s.io/v1/tokenreviews"
    trust = ssl.create_default_context(cafile=str(API/"ca.crt"))
    client = build_opener(ProxyHandler({}), HTTPSHandler(context=trust))
    request = Request(endpoint, data=json.dumps(query).encode(), headers={
        "Content-Type": "application/json", "Authorization": "Bearer "+(API/"token").read_text().strip(),
    })
    with client.open(request, timeout=4) as response:
        status = json.load(response)["status"]
    if status.get("authenticated") and AUDIENCE in status.get("audiences", []):
        return status["user"]["username"]
    return None


def event(**fields):
    print(json.dumps(fields, sort_keys=True), flush=True)


class Endpoint(BaseHTTPRequestHandler):
    def answer(self, status, decision, result=None, retry=None):
        body = json.dumps({"decision": decision, "result": result}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if retry is not None:
            self.send_header("Retry-After", str(retry))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class Predictor(Endpoint):
    def do_GET(self):
        if self.path != "/predict":
            self.answer(404, "route-unknown")
            return
        path = self.headers.get("X-Fixture-Mode")
        if path not in {"baseline", "enforced"}:
            self.answer(400, "fixture-mode-required")
            return
        event(event="prediction", fixture_mode=path)
        self.answer(200, "completed", RESULT)


class Gateway(Endpoint):
    def do_GET(self):
        if self.path != "/predict":
            self.answer(404, "route-unknown")
            return
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            self.answer(401, "credential-required")
            return
        try:
            subject = identify(header.removeprefix("Bearer "))
        except (OSError, ValueError, KeyError):
            self.answer(503, "identity-authority-unavailable")
            return
        if subject not in ALLOWED_SUBJECTS:
            self.answer(401, "credential-unapproved")
            return
        if self.server.mode == "enforced":
            current = time.monotonic()
            until, count = self.server.windows.get(subject, (current+WINDOW, 0))
            if current >= until:
                until, count = current+WINDOW, 0
            if count >= LIMIT:
                event(event="quota-reached", principal=subject, route="predict", status=429)
                self.answer(429, "quota-reached", retry=math.ceil(until-current))
                return
            self.server.windows[subject] = (until, count+1)
        request = Request(PREDICTOR, headers={"X-Fixture-Mode": self.server.mode})
        try:
            with self.server.backend.open(request, timeout=4) as response:
                result = json.load(response)["result"]
        except (OSError, ValueError, KeyError):
            self.answer(503, "predictor-unavailable")
            return
        event(event="forwarded", principal=subject, route="predict", status=200)
        self.answer(200, "approved", result)


def serve(mode):
    if mode == "predictor":
        HTTPServer(("0.0.0.0", 8080), Predictor).serve_forever()
        return
    server = HTTPServer(("0.0.0.0", 8443), Gateway)
    server.windows = {}
    server.mode = mode
    server.backend = build_opener(ProxyHandler({}))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/certificate/tls.crt", "/certificate/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def probe(host, credential):
    context = ssl.create_default_context(cafile="/trust/ca.crt")
    client = HTTPSConnection(host, 8443, context=context, timeout=7)
    try:
        headers = {}
        if credential == "use-projected-token":
            headers["Authorization"] = "Bearer "+Path("/identity/token").read_text().strip()
        client.request("GET", "/predict", headers=headers)
        response = client.getresponse()
        result = {"status": response.status, **json.loads(response.read())}
        retry = response.getheader("Retry-After")
        if retry is not None:
            result["retry_after"] = int(retry)
        print(json.dumps(result))
    finally:
        client.close()


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(sys.argv[2])
    else:
        probe(*sys.argv[2:])
