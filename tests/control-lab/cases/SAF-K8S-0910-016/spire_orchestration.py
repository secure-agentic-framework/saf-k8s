"""SPIRE SVID mTLS probe and bounded placement gateway for the owned fixture."""
from datetime import datetime, timezone
from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request


NS = "saf-test"
WORKLOAD = "fixture-crosscluster-placement"
LABEL = "0910-016"
ALLOWED_SOURCE = "spiffe://src.saf.test/ns/saf-test/sa/fixture-orchestrator-approved"
ALTERNATE_SOURCE = "spiffe://src.saf.test/ns/saf-test/sa/fixture-orchestrator-alternate"
EXPECTED_GATEWAY = "spiffe://peer.saf.test/ns/saf-test/sa/fixture-orchestration-service"
SVID_DIR = Path("/run/svid")
SVID_CERT = SVID_DIR / "svid.0.pem"
SVID_KEY = SVID_DIR / "svid.0.key"
FOREIGN_BUNDLE = SVID_DIR / "federated_bundle.0.0.pem"


def cert_identity(certificate):
    values = [value for kind, value in certificate.get("subjectAltName", ()) if kind == "URI"]
    return values[0] if len(values) == 1 else None


def root_fingerprints(path):
    text = Path(path).read_text(encoding="ascii")
    certificates = []
    start = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    cursor = 0
    while True:
        left = text.find(start, cursor)
        if left < 0:
            break
        right = text.find(end, left)
        if right < 0:
            raise ValueError("malformed bounded trust bundle")
        pem = text[left:right + len(end)]
        certificates.append(hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest())
        cursor = right + len(end)
    return sorted(certificates)


def identity_report(expected):
    decoded = ssl._ssl._test_decode_cert(str(SVID_CERT))
    identities = [value for kind, value in decoded.get("subjectAltName", ()) if kind == "URI"]
    start = ssl.cert_time_to_seconds(decoded["notBefore"])
    end = ssl.cert_time_to_seconds(decoded["notAfter"])
    now = time.time()
    lifetime = end - start
    return {"spiffe_id": identities[0] if len(identities) == 1 else None,
            "expected_id": expected,
            "valid_now": start <= now < end,
            "short_lived": 0 < lifetime <= 630,
            "foreign_bundle_roots": root_fingerprints(FOREIGN_BUNDLE)}


def kube_status(path, payload=None):
    token_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
    try:
        token = token_path.read_text(encoding="utf-8").strip()
    except OSError:
        return 503
    context = ssl.create_default_context(
        cafile="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    request = urllib.request.Request(
        f"https://kubernetes.default.svc{path}", data=payload,
        method="GET" if payload is None else "POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(request, timeout=5) as response:
            response.read(4096)
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except (OSError, urllib.error.URLError):
        return 502


def deployment(name):
    labels = {"saf-fixture": LABEL, "app": name}
    return {"apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": NS, "labels": {"saf-fixture": LABEL}},
        "spec": {"replicas": 1, "selector": {"matchLabels": labels},
            "template": {"metadata": {"labels": labels}, "spec": {
                "automountServiceAccountToken": False,
                "containers": [{"name": "fixture", "image": os.environ["SAF_FIXTURE_IMAGE"],
                    "imagePullPolicy": "Never", "command": ["python", "-c", "import time; time.sleep(3600)"],
                    "securityContext": {"allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True,
                        "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}}}],
            }}}}


def api_create(name):
    body = json.dumps(deployment(name), sort_keys=True, separators=(",", ":")).encode()
    return kube_status(f"/apis/apps/v1/namespaces/{NS}/deployments", body)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def reply(self, status, result):
        body = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        principal = cert_identity(self.connection.getpeercert())
        ready = (self.path == "/ready" and principal == ALLOWED_SOURCE
                 and kube_status("/version") == 200)
        self.reply(200 if ready else 503, {"ready": ready})

    def do_POST(self):
        principal = cert_identity(self.connection.getpeercert())
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 512:
                self.reply(413, {"status": 413, "decision": "refused",
                                 "principal": principal, "server_identity_verified": True})
                return
            request = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            self.reply(400, {"status": 400, "decision": "refused",
                             "principal": principal, "server_identity_verified": True})
            return
        name = request.get("name") if isinstance(request, dict) else None
        if principal != ALLOWED_SOURCE:
            status, decision = 403, "refused"
        elif (not isinstance(request, dict) or request.get("namespace") != NS
              or name != WORKLOAD):
            status, decision = 403, "refused"
        else:
            status = api_create(name)
            decision = "created" if status == 201 else "target-api-refused"
        event = {"event": "orchestration", "principal": principal,
                 "decision": decision, "target_cluster": "peer", "namespace": NS,
                 "name": name if isinstance(name, str) else None, "api_status": status,
                 "peer_certificate_authenticated": bool(self.connection.getpeercert(binary_form=True)),
                 "tls_version_is_1_3": self.connection.version() == "TLSv1.3",
                 "server_identity_verified": True}
        print(json.dumps(event, sort_keys=True, separators=(",", ":")), flush=True)
        self.reply(status, {"status": status, "decision": decision,
                            "principal": principal, "server_identity_verified": True})


def serve():
    if identity_report(EXPECTED_GATEWAY)["spiffe_id"] != EXPECTED_GATEWAY:
        raise SystemExit("gateway SVID selector mismatch")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(SVID_CERT), str(SVID_KEY))
    context.load_verify_locations(cafile=str(FOREIGN_BUNDLE))
    context.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def probe(host, port, expected_server_uri, name, namespace):
    context = ssl.create_default_context(cafile=str(FOREIGN_BUNDLE))
    context.check_hostname = False
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(SVID_CERT), str(SVID_KEY))
    try:
        with socket.create_connection((host, int(port)), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=None) as tls:
                server_uri = cert_identity(tls.getpeercert())
                if server_uri != expected_server_uri:
                    return {"status": 0, "decision": "server-identity-mismatch"}
                if name == "fixture-readiness":
                    tls.sendall(b"GET /ready HTTP/1.0\r\n\r\n")
                else:
                    payload = json.dumps({"namespace": namespace, "name": name}).encode()
                    tls.sendall(b"POST /orchestrate HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: "
                                + str(len(payload)).encode() + b"\r\n\r\n" + payload)
                response = HTTPResponse(tls)
                response.begin()
                body = response.read(2048)
                result = json.loads(body)
                if name == "fixture-readiness":
                    return result
                result["server_identity_verified"] = True
                return result
    except (OSError, EOFError, ValueError, ssl.SSLError):
        return {"status": 0, "decision": "transport-or-trust-error"}


if __name__ == "__main__":
    command = sys.argv[1]
    if command == "serve":
        serve()
    elif command == "identity":
        print(json.dumps(identity_report(sys.argv[2]), sort_keys=True, separators=(",", ":")))
    elif command == "probe":
        result = probe(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6])
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        raise SystemExit("unknown fixture command")
