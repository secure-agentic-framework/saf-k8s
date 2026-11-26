"""Inert local role-boundary fixture; it never calls a model or external service."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import ssl
import urllib.request

MODE = os.environ.get("POLICY_MODE", "")
TRUSTED_SYSTEM = "Fixture system context."
TRUSTED_DEVELOPER = "Fixture developer context."
BACKEND = {"dispatch_count": 0, "last_messages": [], "last_roles": []}


def build_trusted_messages(content):
    return [
        {"role": "system", "content": TRUSTED_SYSTEM},
        {"role": "developer", "content": TRUSTED_DEVELOPER},
        {"role": "user", "content": content},
    ]


def dispatch(messages):
    """Record only local fixture messages and return a fixed harmless answer."""
    BACKEND["dispatch_count"] += 1
    BACKEND["last_messages"] = messages
    BACKEND["last_roles"] = [message["role"] for message in messages]
    return "4"


def verified_role(bearer):
    """Ask the owned API server to authenticate the projected client token."""
    if not isinstance(bearer, str) or not bearer.startswith("Bearer "):
        return None
    client_token = bearer[7:].strip()
    if not client_token or len(client_token) > 16384:
        return None
    try:
        from pathlib import Path
        root = Path("/var/run/secrets/kubernetes.io/serviceaccount")
        reviewer_token = (root / "token").read_text(encoding="utf-8").strip()
        request_body = json.dumps({
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenReview",
            "spec": {"token": client_token,
                     "audiences": ["https://kubernetes.default.svc.cluster.local"]},
        }).encode("utf-8")
        request = urllib.request.Request(
            "https://kubernetes.default.svc/apis/authentication.k8s.io/v1/tokenreviews",
            data=request_body,
            headers={"Authorization": "Bearer " + reviewer_token,
                     "Content-Type": "application/json"},
        )
        context = ssl.create_default_context(cafile=str(root / "ca.crt"))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=context))
        with opener.open(request, timeout=3) as response:
            if response.status != 201:
                return None
            result = json.loads(response.read(65537))
        status = result.get("status", {})
        if status.get("authenticated") is not True:
            return None
        if "https://kubernetes.default.svc.cluster.local" not in status.get("audiences", []):
            return None
        return status.get("user", {}).get("username")
    except Exception:
        # Never log a token, API response, URL, or exception detail.
        return None


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body):
        encoded = json.dumps(body, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ready": True, "mode": MODE})
        elif self.path == "/state":
            self._send(200, {"mode": MODE, **BACKEND})
        else:
            self._send(404, {"reason": "not_found"})

    def do_POST(self):
        if self.path != "/public":
            self._send(404, {"reason": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 4096:
                self._send(400, {"reason": "invalid_size"})
                return
            request = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            self._send(400, {"reason": "invalid_json"})
            return
        if not isinstance(request, dict):
            self._send(400, {"reason": "invalid_shape"})
            return

        effective_role = None
        if MODE == "role-source":
            principal = verified_role(self.headers.get("Authorization", ""))
            if principal is None:
                self._send(401, {"reason": "identity_unverified"})
                return
            if principal == "system:serviceaccount:saf-test:inference-user":
                effective_role = "user"
            else:
                self._send(403, {"reason": "principal_not_approved"})
                return
            if set(request) - {"role", "content"}:
                self._send(400, {"reason": "unsupported_field"})
                return
            if "role" in request and request.get("role") != effective_role:
                self._send(403, {"reason": "role_source_conflict"})
                return

        if MODE in ("on", "role-source"):
            if "developer" in request or "system" in request:
                self._send(400, {"reason": "reserved_role_field"})
                return
            required_fields = {"role", "content"} if MODE == "on" else {"content"}
            if not required_fields <= set(request) <= {"role", "content"}:
                self._send(400, {"reason": "unsupported_field"})
                return
        role = effective_role if MODE == "role-source" else request.get("role")
        content = request.get("content")
        if role != "user":
            self._send(400, {"reason": "unknown_role"})
            return
        if not isinstance(content, str) or not content or len(content) > 256:
            self._send(400, {"reason": "invalid_content"})
            return

        messages = build_trusted_messages(content)
        answer = dispatch(messages)
        body = {"accepted": True, "answer": answer,
                "metadata_ignored": "metadata" in request}
        if MODE == "role-source":
            body.update({"identity_authenticated": True,
                         "identity_role": effective_role,
                         "identity_binding": "approved-inference-user-serviceaccount",
                         "identity_source": "projected-serviceaccount-tokenreview"})
        self._send(200, body)

    def log_message(self, *_args):
        pass


server = HTTPServer(("0.0.0.0", 8080), Handler)
if MODE == "role-source":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/fixture-tls/tls.crt", "/fixture-tls/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
