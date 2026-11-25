"""Minimal case-owned promotion endpoint backed by Kubernetes TokenReview."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import base64
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


def _review(token, audience):
    # Native external JWT authentication uses the API's implicit TokenReview
    # audience. The configured OIDC authenticator validates the JWT audience.
    spec = {"token": token}
    if audience is not None:
        spec["audiences"] = [audience]
    request_body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": spec}
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
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"tokenreview-http-{error.code}") from None
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        raise RuntimeError("tokenreview-transport-or-response") from None
    status = result.get("status", {})
    return {"http_status": 201,
            "authenticated": status.get("authenticated") is True,
            "username": status.get("user", {}).get("username"),
            "audiences": sorted(status.get("audiences", [])),
            "groups": sorted(status.get("user", {}).get("groups", []))}


def _claims_after_native_auth(token):
    # Called only after TokenReview confirms this exact bearer token's signature,
    # issuer, audience, expiry, and required class with the Kubernetes API server.
    try:
        _header, payload, _signature = token.split(".", 2)
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload.encode()))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    return claims if isinstance(claims, dict) else None


def _is_human_allowed(identity, token, decision):
    reviewer = os.environ["HUMAN_REVIEWER_USERNAME"]
    if (not identity["authenticated"] or identity["username"] != reviewer or
            "oidc-fixture:reviewers" not in identity["groups"]):
        return False, "identity-or-group-rejected"
    claims = _claims_after_native_auth(token)
    if claims is None:
        return False, "claims-unavailable"
    expected = {"model": "saf-fixture-model-v1", "environment": "production",
                "artifact_digest": "sha256:" + "a" * 64}
    if claims.get("aud") != os.environ["PROMOTION_AUDIENCE"]:
        return False, "approval-audience-rejected"
    if (claims.get("session") != "session-fixture-01" or
            claims.get("approval_path") != expected or decision != expected):
        return False, "session-or-path-rejected"

    # Native RBAC is the revocable grant: the TokenReview service account asks
    # the API server whether this mapped human may read only the fixture approval.
    reviewer_token = TOKEN_PATH.read_text().strip()
    sar = {"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
           "spec": {"user": identity["username"], "groups": identity["groups"],
                    "resourceAttributes": {"namespace": "saf-test", "verb": "get",
                                           "group": "", "resource": "configmaps",
                                           "name": "promotion-approval"}}}
    request = urllib.request.Request(
        "https://kubernetes.default.svc/apis/authorization.k8s.io/v1/subjectaccessreviews",
        data=json.dumps(sar).encode(), method="POST",
        headers={"Authorization": "Bearer " + reviewer_token,
                 "Content-Type": "application/json"})
    context = ssl.create_default_context(cafile=CA_PATH)
    try:
        with urllib.request.urlopen(request, context=context, timeout=5) as response:
            result = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        raise RuntimeError("SubjectAccessReview unavailable") from None
    allowed = result.get("status", {}).get("allowed") is True
    return allowed, "native-rbac-grant" if allowed else "native-rbac-grant-withdrawn"


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
        if decision not in (
                {"model": "saf-fixture-model-v1", "environment": "production"},
                {"model": "saf-fixture-model-v1", "environment": "production",
                 "artifact_digest": "sha256:" + "a" * 64}):
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
        human_mode = bool(os.environ.get("HUMAN_REVIEWER_USERNAME"))
        audience = None if human_mode else os.environ["PROMOTION_AUDIENCE"]
        try:
            identity = _review(token, audience)
        except RuntimeError as error:
            details = str(error)
            allowed_details = {"tokenreview-http-400", "tokenreview-http-401",
                               "tokenreview-http-403", "tokenreview-http-500",
                               "tokenreview-http-503", "tokenreview-transport-or-response"}
            self._reply(503, {"error": "identity-review-unavailable",
                              "reason": details if details in allowed_details else "tokenreview-failed"})
            return
        if human_mode:
            try:
                accepted, reason = _is_human_allowed(identity, token, decision)
            except RuntimeError:
                self._reply(503, {"error": "authorization-review-unavailable"})
                return
        else:
            accepted = _is_allowed(identity, os.environ["REVIEWER_USERNAME"],
                                   os.environ["PROMOTION_AUDIENCE"])
            reason = "reviewer-accepted" if accepted else "identity-or-audience-rejected"
        self._reply(200 if accepted else 403,
                    {"accepted": bool(accepted),
                     "reason": reason,
                     "identity": identity})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
