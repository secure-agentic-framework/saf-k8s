"""Minimal case-owned promotion endpoint backed by Kubernetes TokenReview."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.request


TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


def _is_allowed(identity, reviewer, audience):
    return (identity["authenticated"] and identity["username"] == reviewer and
            audience in identity["audiences"])


def _review(token):
    # The token is held only in memory and sent directly to the in-cluster API server.
    request_body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                    "spec": {"token": token,
                             "audiences": [os.environ["PROMOTION_AUDIENCE"]]}}
    reviewer_token = TOKEN_PATH.read_text().strip()
    request = urllib.request.Request(
        "https://kubernetes.default.svc/apis/authentication.k8s.io/v1/tokenreviews",
        data=json.dumps(request_body).encode(), method="POST",
        headers={"Authorization": "Bearer " + reviewer_token,
                 "Content-Type": "application/json"})
    context = ssl.create_default_context(cafile=CA_PATH)
    try:
        with urllib.request.urlopen(request, context=context, timeout=5) as response:
            if response.status != 201:
                raise RuntimeError("unexpected TokenReview response")
            result = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise RuntimeError("TokenReview unavailable") from error
    status = result.get("status", {})
    return {"http_status": 201,
            "authenticated": status.get("authenticated") is True,
            "username": status.get("user", {}).get("username"),
            "audiences": sorted(status.get("audiences", []))}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        # BaseHTTPRequestHandler would log request metadata. Keep fixture logs empty of identities.
        return

    def _reply(self, code, payload):
        encoded = json.dumps(payload, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path == "/healthz":
            self._reply(200, {"ready": True})
        else:
            self._reply(404, {"error": "not-found"})

    def do_POST(self):
        if self.path != "/decision":
            self._reply(404, {"error": "not-found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 2048:
                self._reply(413, {"error": "decision-too-large"})
                return
            decision = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            self._reply(400, {"error": "invalid-decision"})
            return
        if decision != {"model": "saf-fixture-model-v1", "environment": "production"}:
            self._reply(400, {"error": "unexpected-decision"})
            return

        authorization = self.headers.get("Authorization", "")
        token = authorization[7:] if authorization.startswith("Bearer ") else ""
        if os.environ.get("ENFORCE_REVIEWER") != "true":
            accepted = bool(token)
            self._reply(200 if accepted else 403,
                        {"accepted": accepted, "reason": "gate-disabled" if accepted
                         else "missing-credential"})
            return
        if not token:
            self._reply(403, {"accepted": False, "reason": "missing-credential",
                              "identity": None})
            return
        try:
            identity = _review(token)
        except RuntimeError:
            self._reply(503, {"error": "identity-review-unavailable"})
            return
        accepted = _is_allowed(identity, os.environ["REVIEWER_USERNAME"],
                               os.environ["PROMOTION_AUDIENCE"])
        self._reply(200 if accepted else 403,
                    {"accepted": bool(accepted),
                     "reason": "reviewer-accepted" if accepted else "identity-or-audience-rejected",
                     "identity": identity})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
