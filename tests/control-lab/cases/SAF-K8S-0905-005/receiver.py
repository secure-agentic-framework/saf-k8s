"""Fail-closed Deployment admission over the exact persisted synthetic evidence."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import urllib.error
import urllib.parse
import urllib.request

from gate import EVIDENCE_NAME, NAMESPACE, _evaluate


TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
TLS_CERT = "/tls/tls.crt"
TLS_KEY = "/tls/tls.key"
API = "https://kubernetes.default.svc"
MODEL_ANNOTATION = "saf.example/model-sha256"


def _get_evidence():
    token = TOKEN_PATH.read_text().strip()
    path = f"/api/v1/namespaces/{NAMESPACE}/configmaps/{EVIDENCE_NAME}"
    request = urllib.request.Request(
        API + path, headers={"Authorization": "Bearer " + token})
    context = ssl.create_default_context(cafile=CA_PATH)
    try:
        with urllib.request.urlopen(request, context=context, timeout=3) as response:
            resource = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        raise RuntimeError("evidence-read-failed") from None
    raw = resource.get("data", {}).get("evidence.json")
    if not raw:
        raise ValueError("evidence-not-approved")
    try:
        evidence = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        raise ValueError("evidence-not-approved") from None
    return evidence


def _decision(admission):
    request = admission.get("request", {})
    uid = request.get("uid", "")
    if (request.get("operation") != "CREATE" or
            request.get("kind") != {"group": "apps", "version": "v1",
                                     "kind": "Deployment"} or
            request.get("resource") != {"group": "apps", "version": "v1",
                                         "resource": "deployments"} or
            request.get("namespace") != NAMESPACE):
        return uid, False, "out-of-scope-request"
    deployment = request.get("object") or {}
    annotations = deployment.get("metadata", {}).get("annotations", {})
    supplied_digest = annotations.get(MODEL_ANNOTATION)
    if not isinstance(supplied_digest, str):
        return uid, False, "model-digest-missing"
    try:
        evidence = _get_evidence()
        verdict = _evaluate(evidence)
    except (OSError, RuntimeError):
        return uid, False, "evidence-read-failed"
    except ValueError:
        return uid, False, "evidence-not-approved"
    if verdict.get("accepted") is not True:
        return uid, False, "evidence-not-approved"
    if supplied_digest != verdict.get("model_sha256"):
        return uid, False, "model-digest-mismatch"
    return uid, True, "approved-model-digest"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
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
        if urllib.parse.urlsplit(self.path).path != "/validate":
            self._reply(404, {"error": "not-found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 131072:
                self._reply(413, {"error": "invalid-request-size"})
                return
            admission = json.loads(self.rfile.read(length))
        except (ValueError, TypeError, json.JSONDecodeError):
            self._reply(400, {"error": "invalid-request"})
            return
        uid, allowed, reason = _decision(admission)
        response = {"uid": uid, "allowed": allowed}
        if not allowed:
            response["status"] = {"code": 403, "message": reason}
        self._reply(200, {"apiVersion": "admission.k8s.io/v1",
                          "kind": "AdmissionReview", "response": response})


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(TLS_CERT, TLS_KEY)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
