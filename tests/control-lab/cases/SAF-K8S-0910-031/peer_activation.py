"""Owned peer-cluster identity verifier for SAF-K8S-0910-031."""
import json
import os
from pathlib import Path
import tempfile
import time

from fixtures import container, pod, ready


NS = "saf-test"
APPROVED = "fixture-enrollment-approved"
UNAPPROVED = "fixture-enrollment-unapproved"
OWNER = "fixture-destination-endpoint-owner"
SERVICE = "fixture-destination-owner-verifier"
CODE = "fixture-destination-owner-verifier-code"
HOST = "fixture-destination-owner.saf.test"


def _write_secret(peer, cert, key, directory):
    import json as json_module
    descriptor, filename = tempfile.mkstemp(prefix="saf-0910-031-peer-tls-", suffix=".json",
                                           dir=directory)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(json_module.dumps({"apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": "fixture-destination-owner-tls", "namespace": NS},
                "type": "kubernetes.io/tls", "stringData": {
                    "tls.crt": cert.read_text(encoding="ascii"),
                    "tls.key": key.read_text(encoding="ascii"),
                }}))
            stream.flush()
            os.fsync(stream.fileno())
        peer("create", "-f", filename, "-o", "name")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        Path(filename).unlink(missing_ok=True)


def material(lab, directory):
    root = Path(directory)
    ca_key, ca_cert = root / "peer-owner-ca.key", root / "peer-owner-ca.crt"
    key, csr, cert, extensions = (root / name for name in (
        "peer-owner.key", "peer-owner.csr", "peer-owner.crt", "peer-owner.ext"))
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=saf-0910-031-peer-owner-ca",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash", "-keyout", str(ca_key),
                "-out", str(ca_cert), timeout=30)
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:fixture-destination-owner.saf.test\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n", encoding="ascii")
    lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj",
                "/CN=fixture-destination-endpoint-owner", "-keyout", str(key),
                "-out", str(csr), timeout=30)
    lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
                "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1", "-sha256",
                "-extfile", str(extensions), "-out", str(cert), timeout=30)
    for path in (ca_key, key):
        path.chmod(0o600)
    return ca_cert, cert, key


def install(lab, peer, image, peer_ip, approved_port, directory):
    ca_cert, cert, key = material(lab, directory)
    peer("create", "serviceaccount", OWNER)
    peer("create", "-f", "-", payload=json.dumps({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": OWNER, "namespace": NS}, "rules": [{
            "apiGroups": [""], "resources": ["services"], "resourceNames": [APPROVED],
            "verbs": ["get"],
        }]}))
    peer("create", "-f", "-", payload=json.dumps({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": OWNER, "namespace": NS},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": OWNER},
        "subjects": [{"kind": "ServiceAccount", "name": OWNER, "namespace": NS}],
    }))
    _write_secret(peer, cert, key, directory)
    peer("create", "-f", "-", "-o", "name", payload=json.dumps({
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CODE},
        "immutable": True,
        "data": {"peer_activation.py": PEER_SCRIPT},
    }))
    unit = container("verifier", image=image, imagePullPolicy="Never",
        command=["python", "/fixture/peer_activation.py"],
        ports=[{"containerPort": 9443}],
        readinessProbe={"tcpSocket": {"port": 9443}, "periodSeconds": 1},
        env=[{"name": "PEER_NODE_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.hostIP"}}},
             {"name": "APPROVED_PORT", "value": str(approved_port)}],
        volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True},
                      {"name": "tls", "mountPath": "/tls", "readOnly": True}])
    definition = pod(SERVICE, [unit], serviceAccountName=OWNER,
        volumes=[{"name": "code", "configMap": {"name": CODE}},
                 {"name": "tls", "secret": {"secretName": "fixture-destination-owner-tls",
                                                "defaultMode": 0o440}}],
        securityContext={"fsGroup": 65534},
        automountServiceAccountToken=True)
    definition["metadata"]["labels"] = {"app": SERVICE}
    peer("create", "-f", "-", payload=json.dumps(definition))
    service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": SERVICE},
        "spec": {"type": "NodePort", "selector": {"app": SERVICE},
                 "ports": [{"name": "https", "port": 9443, "targetPort": 9443}]}}
    result = peer("create", "-f", "-", "-o", "json", payload=json.dumps(service))
    port = json.loads(result.stdout)["spec"]["ports"][0]["nodePort"]
    peer("wait", "--for=condition=Ready", f"pod/{SERVICE}", "--timeout=90s", timeout=100)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "fixture-destination-owner-ca", "namespace": NS},
        "immutable": True,
        "data": {"ca.crt": ca_cert.read_text(encoding="ascii")}})
    return {"host": HOST, "port": port, "node_ip": peer_ip, "approved_port": approved_port}


PEER_SCRIPT = r'''"""Read one live peer Service as a scoped Kubernetes workload identity."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json, os, ssl, urllib.error, urllib.request

NS = "saf-test"
APPROVED = "fixture-enrollment-approved"
UNAPPROVED = "fixture-enrollment-unapproved"
NODE_IP = os.environ["PEER_NODE_IP"]
PORT = int(os.environ["APPROVED_PORT"])

def api_get(name):
    token = open("/var/run/secrets/kubernetes.io/serviceaccount/token", encoding="utf-8").read().strip()
    context = ssl.create_default_context(cafile="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    request = urllib.request.Request(
        "https://kubernetes.default.svc/api/v1/namespaces/" + NS + "/services/" + name,
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(request, timeout=4) as response:
            raw = response.read(65536)
            return response.status, json.loads(raw) if response.status == 200 else None
    except urllib.error.HTTPError as error:
        return error.code, None
    except (OSError, urllib.error.URLError):
        return 502, None

def snapshot():
    status, service = api_get(APPROVED)
    denied_status, _ = api_get(UNAPPROVED)
    if status != 200 or not service:
        return None, {"read_exact_service_allowed": False,
                      "unapproved_service_read_denied": denied_status == 403}
    ports = service.get("spec", {}).get("ports", [])
    row = next((item for item in ports if item.get("port") == 5000), None)
    node_port = row.get("nodePort") if row else None
    valid = (service.get("metadata", {}).get("name") == APPROVED
             and service.get("metadata", {}).get("namespace") == NS
             and service.get("spec", {}).get("type") == "NodePort"
             and isinstance(service.get("metadata", {}).get("uid"), str)
             and row is not None and node_port == PORT and row.get("targetPort") == 5000
             and NODE_IP and not NODE_IP.startswith(("127.", "169.254.")))
    if not valid:
        return None, {"read_exact_service_allowed": True,
                      "unapproved_service_read_denied": denied_status == 403}
    return {"service_uid": service["metadata"]["uid"],
            "endpoint": "http://" + NODE_IP + ":" + str(node_port)}, {
                "read_exact_service_allowed": True,
                "unapproved_service_read_denied": denied_status == 403}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return
    def do_GET(self):
        value, checks = snapshot()
        if self.path != "/snapshot" or value is None:
            status, result = 403, {"decision": "peer-service-unavailable", **checks}
        else:
            status, result = 200, {"decision": "peer-service-current", **value, **checks}
        body = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

server = ThreadingHTTPServer(("0.0.0.0", 9443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
'''
