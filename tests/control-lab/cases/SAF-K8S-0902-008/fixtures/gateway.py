"""Authenticate fixed fixture identities and authorize access to owned model mocks."""
import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import time
from urllib.error import URLError
from urllib.request import Request, ProxyHandler, build_opener


KEY = Path("/run/test-key/key").read_bytes()
POLICY = json.loads(Path("/case/policy.json").read_text())["identities"]
ENFORCE = os.environ["GATEWAY_MODE"] == "enforced"
MODELS = {"model-alpha", "model-beta"}
EVENTS = {"red-absent", "red-wrong-model", "green-absent", "green-expired",
          "green-wrong-model", "positive-alpha", "positive-beta"}


def decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def authenticate(token):
    try:
        if len(token) > 1024:
            return None
        header, payload, signature = token.split(".")
        actual = hmac.new(KEY, f"{header}.{payload}".encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(actual, decode(signature)):
            return None
        if json.loads(decode(header)) != {"alg": "HS256", "typ": "JWT"}:
            return None
        claims = json.loads(decode(payload))
        subject = claims["sub"]
        if (claims["iss"] != "saf-0902-008-local-issuer"
                or claims["aud"] != "saf-0902-008-fixture"
                or type(claims["exp"]) is not int or claims["exp"] <= time.time()
                or subject not in POLICY or claims["models"] != POLICY[subject]):
            return None
        return subject
    except (ValueError, TypeError, KeyError):
        return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def send_body(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def report(self, event, model, principal, decision, status, response, backend_status=None):
        print(json.dumps({"event_id": event, "model": model, "principal": principal,
                          "decision": decision, "status": status, "backend_status": backend_status},
                         sort_keys=True), flush=True)
        self.send_body(status, response)

    def do_GET(self):
        elements = self.path.split("/")
        model = elements[3] if len(elements) == 5 and elements[:3] == ["", "v1", "models"] else ""
        event = self.headers.get("X-Fixture-Event-ID")
        if model not in MODELS or elements[4] != "infer" or event not in EVENTS:
            self.send_body(404, b'{"result":"not-found"}')
            return
        principal = "unauthenticated"
        if ENFORCE:
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                self.report(event, model, principal, "deny-no-token", 401, b'{"result":"authentication-required"}')
                return
            principal = authenticate(auth[7:])
            if principal is None:
                self.report(event, model, "unauthenticated", "deny-invalid-token", 401,
                            b'{"result":"authentication-required"}')
                return
            if model not in POLICY[principal]:
                self.report(event, model, principal, "deny-model", 403, b'{"result":"model-not-authorized"}')
                return
        try:
            request = Request(f"http://{model}:8081/infer", headers={"X-Fixture-Event-ID": event})
            with build_opener(ProxyHandler({})).open(request, timeout=4) as response:
                body = response.read(512)
                backend_status = response.status
        except (URLError, OSError):
            self.report(event, model, principal, "backend-unavailable", 502, b'{"result":"backend-unavailable"}')
            return
        self.report(event, model, principal, "allow", 200, body, backend_status)


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
