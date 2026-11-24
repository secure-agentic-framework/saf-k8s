"""Bounded mTLS orchestration gateway and fixed-action probe for SAF-K8S-0910-016."""
from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.request

ALLOWED_URI = "spiffe://saf.test/ns/saf-test/sa/fixture-orchestrator-approved"
NAMESPACE = "saf-test"
WORKLOAD = "fixture-crosscluster-placement"
LABEL = "0910-016"


def identity(connection):
    cert = connection.getpeercert()
    uris = [value for scheme, value in cert.get("subjectAltName", ()) if scheme == "URI"]
    return uris[0] if len(uris) == 1 else None


def deployment(name):
    labels = {"saf-fixture": LABEL, "app": name}
    return {"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": name, "namespace": NAMESPACE,
                         "labels": {"saf-fixture": LABEL}},
            "spec": {"replicas": 1, "selector": {"matchLabels": labels},
                     "template": {"metadata": {"labels": labels}, "spec": {
                         "automountServiceAccountToken": False, "terminationGracePeriodSeconds": 3,
                         "containers": [{"name": "fixture", "image": os.environ["SAF_FIXTURE_IMAGE"],
                                         "imagePullPolicy": "Never", "command": ["python", "-c", "import time; time.sleep(3600)"],
                                         "securityContext": {"allowPrivilegeEscalation": False,
                                                             "capabilities": {"drop": ["ALL"]},
                                                             "runAsNonRoot": True, "runAsUser": 65534,
                                                             "seccompProfile": {"type": "RuntimeDefault"}}}],
                     }}}}


def kube_status(path, payload=None):
    token = open("/var/run/secrets/kubernetes.io/serviceaccount/token", encoding="utf-8").read().strip()
    context = ssl.create_default_context(cafile="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    request = urllib.request.Request(
        f"https://kubernetes.default.svc{path}",
        data=payload, method="GET" if payload is None else "POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=context))
        with opener.open(request, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except (OSError, urllib.error.URLError):
        return 502


def api_create(name):
    return kube_status(f"/apis/apps/v1/namespaces/{NAMESPACE}/deployments",
                       json.dumps(deployment(name)).encode())


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def reply(self, status, payload):
        body = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        ready = (self.path == "/ready" and identity(self.connection) == ALLOWED_URI
                 and kube_status("/version") == 200)
        self.reply(200 if ready else 503, {"ready": ready})

    def do_POST(self):
        who = identity(self.connection)
        mode = self.server.mode
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 512:
                self.reply(413, {"status": 413, "decision": "refused", "reason": "request-too-large"})
                return
            request = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            self.reply(400, {"status": 400, "decision": "refused", "reason": "invalid-request"})
            return
        name = request.get("name") if isinstance(request, dict) else None
        if mode == "enforced" and who != ALLOWED_URI:
            status, decision, reason = 403, "refused", "identity-not-approved"
        elif not isinstance(request, dict) or request.get("namespace") != NAMESPACE or name != WORKLOAD:
            status, decision, reason = 403, "refused", "placement-not-approved"
        else:
            status = api_create(name)
            decision, reason = ("created", None) if status == 201 else ("target-api-refused", None)
        event = {"event": "orchestration", "mode": mode, "principal": who,
                 "decision": decision, "target_cluster": "peer", "namespace": NAMESPACE,
                 "name": name if isinstance(name, str) else None, "api_status": status}
        print(json.dumps(event, sort_keys=True), flush=True)
        payload = {"status": status, "decision": decision, "principal": who}
        if reason:
            payload["reason"] = reason
        self.reply(status, payload)


def serve():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    context.load_verify_locations("/tls/ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.mode = sys.argv[2]
    server.serve_forever()


def probe(host, port, server_name, name, namespace):
    context = ssl.create_default_context(cafile="/tls/ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    try:
        with socket.create_connection((host, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=server_name) as tls:
                payload = json.dumps({"namespace": namespace, "name": name}).encode()
                if name == "fixture-readiness":
                    tls.sendall(b"GET /ready HTTP/1.0\r\n\r\n")
                else:
                    tls.sendall(b"POST /orchestrate HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: "
                                + str(len(payload)).encode() + b"\r\n\r\n" + payload)
                response = HTTPResponse(tls)
                response.begin()
                return json.load(response)
    except (OSError, EOFError, ValueError) as error:
        return {"status": 0, "decision": "transport-error",
                "detail": f"{type(error).__name__}: {error}"}


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve()
    else:
        print(json.dumps(probe(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6]),
                         sort_keys=True))
