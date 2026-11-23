"""Verify one fixed Kubernetes management read through an audited, private relay."""
import base64
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import socket
import ssl
import subprocess
import threading
from urllib.parse import urlsplit

API_PATH = "/api/v1/namespaces/saf-test/configmaps/managed-path-proof"
RELAY_PATH = "/fixture-admin-read"
SERVER_NAME = "relay.fixture.saf"
APPROVED = "spiffe://fixture.saf/admin/approved"
OTHER = "spiffe://fixture.saf/admin/other"
MARKER = "verified-private-admin-path"
SCOPE = (
    "One owned Kind cluster and a loopback-only private relay for a single harmless Kubernetes "
    "read. Both verified client identities can read before authorization. After the rule, "
    "the other identity receives 403 before an API request, and the approved identity still "
    "reads the exact API object. The relay verifies its client and API identities independently "
    "and keeps decision records. Production routing, VPN or bastion, MFA, and log delivery "
    "require separate evidence."
)


def keypair(lab, folder, name, ca_pair=None, extension=None):
    key, cert = folder / f"{name}.key", folder / f"{name}.pem"
    args = ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-sha256",
            "-subj", f"/CN=SAF fixture {name}", "-keyout", str(key)]
    if ca_pair is None:
        config = folder / "ca.ini"
        config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=v3\n[dn]\n"
                          "[v3]\nbasicConstraints=critical,CA:true\n"
                          "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
        lab.command(*args, "-x509", "-days", "1", "-config", str(config), "-out", str(cert))
    else:
        csr, ext = folder / f"{name}.csr", folder / f"{name}.ext"
        usage, san = extension
        ext.write_text("basicConstraints=critical,CA:FALSE\n"
                       "keyUsage=critical,digitalSignature,keyEncipherment\n"
                       "authorityKeyIdentifier=keyid\n"
                       f"extendedKeyUsage={usage}\nsubjectAltName={san}\n")
        lab.command(*args, "-new", "-out", str(csr))
        lab.command("openssl", "x509", "-req", "-sha256", "-days", "1", "-in", str(csr),
                    "-CA", str(ca_pair[0]), "-CAkey", str(ca_pair[1]), "-CAcreateserial",
                    "-extfile", str(ext), "-out", str(cert))
    key.chmod(0o600)
    return cert, key


def provision(lab):
    lab.kubectl("create", "configmap", "managed-path-proof", f"--from-literal=marker={MARKER}")
    lab.kubectl("create", "serviceaccount", "managed-path-relay")
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "managed-path-relay"},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"],
                   "resourceNames": ["managed-path-proof"]}],
    })
    lab.kubectl("create", "rolebinding", "managed-path-relay", "--role=managed-path-relay",
                "--serviceaccount=saf-test:managed-path-relay")
    # A short-lived fixture token stays in memory and out of the command transcript.
    response = subprocess.run(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
         "-n", "saf-test", "create", "token", "managed-path-relay", "--duration=10m"],
        capture_output=True, text=True, env=lab.env, timeout=20,
    )
    token = response.stdout.strip()
    if response.returncode or len(token.split(".")) != 3:
        lab.block("Unable to obtain the disposable scoped relay identity")
    return token


def read_api(port, context, token):
    connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=9, context=context)
    try:
        connection.request("GET", API_PATH, headers={"Authorization": "Bearer " + token})
        result = connection.getresponse()
        body = json.loads(result.read(16384))
        return (result.status == 200 and body.get("kind") == "ConfigMap"
                and body["metadata"]["name"] == "managed-path-proof"
                and body["metadata"]["namespace"] == "saf-test"
                and body.get("data", {}).get("marker") == MARKER)
    finally:
        connection.close()


class Relay(BaseHTTPRequestHandler):
    def do_GET(self):
        uris = [value for kind, value in self.connection.getpeercert().get("subjectAltName", ())
                if kind == "URI"]
        if self.path != RELAY_PATH or uris not in ([APPROVED], [OTHER]):
            self.respond(404, {})
            return
        identity = uris[0]
        if self.server.restricted and identity != APPROVED:
            self.server.audit.append({"identity": identity, "decision": "denied", "api_contacted": False})
            self.respond(403, {"decision": "denied"})
            return
        self.server.audit.append({"identity": identity, "decision": "allowed", "api_contacted": True})
        try:
            valid = read_api(self.server.api_port, self.server.api_context, self.server.token)
        except (OSError, ValueError, KeyError, http.client.HTTPException):
            valid = False
        self.respond(200 if valid else 502, {"api_marker_verified": valid})

    def respond(self, status, body):
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        return


def probe(port, ca, pair):
    context = ssl.create_default_context(cafile=str(ca))
    context.load_cert_chain(*pair)
    with socket.create_connection(("127.0.0.1", port), timeout=9) as raw:
        with context.wrap_socket(raw, server_hostname=SERVER_NAME) as secure:
            secure.sendall(f"GET {RELAY_PATH} HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: close\r\n\r\n".encode())
            result = http.client.HTTPResponse(secure)
            result.begin()
            return {"status": result.status, "body": json.loads(result.read(2048))}


def run(lab):
    address = lab.kubectl("config", "view", "--minify",
                          "-o", "jsonpath={.clusters[0].cluster.server}").stdout
    endpoint = urlsplit(address)
    if endpoint.scheme != "https" or endpoint.hostname != "127.0.0.1" or not endpoint.port:
        lab.block("Expected the current owned Kind API on loopback")
    raw_ca = lab.kubectl("config", "view", "--minify", "--raw",
                         "-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}").stdout
    api_trust = ssl.create_default_context(cadata=base64.b64decode(raw_ca, validate=True).decode())
    token = provision(lab)
    folder = lab.kubeconfig.parent / "relay-certs"
    folder.mkdir(mode=0o700)
    ca_pair = keypair(lab, folder, "root")
    server = keypair(lab, folder, "relay", ca_pair, ("serverAuth", f"DNS:{SERVER_NAME}"))
    clients = {
        name: keypair(lab, folder, name, ca_pair, ("clientAuth", f"URI:{identity}"))
        for name, identity in (("approved", APPROVED), ("other", OTHER))
    }
    trust = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    trust.load_cert_chain(*server)
    trust.load_verify_locations(cafile=str(ca_pair[0]))
    trust.verify_mode = ssl.CERT_REQUIRED

    with HTTPServer(("127.0.0.1", 0), Relay) as gateway:
        gateway.socket = trust.wrap_socket(gateway.socket, server_side=True)
        gateway.restricted = False
        gateway.audit = []
        gateway.api_port = endpoint.port
        gateway.api_context = api_trust
        gateway.token = token
        worker = threading.Thread(target=gateway.serve_forever, daemon=True)
        worker.start()
        try:
            expected = {"status": 200, "body": {"api_marker_verified": True}}
            before = {name: probe(gateway.server_port, ca_pair[0], pair) for name, pair in clients.items()}
            lab.check("red", "Both enrolled clients read the real API fixture before relay authorization",
                      all(v == expected for v in before.values()), before)
            gateway.restricted = True
            denied = probe(gateway.server_port, ca_pair[0], clients["other"])
            negative = {"identity": OTHER, "decision": "denied", "api_contacted": False}
            lab.check("green", "The other verified identity is denied before a Kubernetes API request",
                      denied == {"status": 403, "body": {"decision": "denied"}} and gateway.audit[-1] == negative,
                      {"status": denied["status"], **gateway.audit[-1]})
            allowed = probe(gateway.server_port, ca_pair[0], clients["approved"])
            positive = {"identity": APPROVED, "decision": "allowed", "api_contacted": True}
            lab.check("positive", "The approved identity still reads the marker through the audited relay",
                      allowed == expected and gateway.audit[-1] == positive,
                      {"status": allowed["status"], **gateway.audit[-1]})
            expected_sequence = [(APPROVED, "allowed"), (OTHER, "allowed"),
                                 (OTHER, "denied"), (APPROVED, "allowed")]
            lab.check("positive", "The relay records each reviewed management path decision",
                      [(row["identity"], row["decision"]) for row in gateway.audit] == expected_sequence,
                      {"event_count": len(gateway.audit)})
            (lab.evidence / "managed-path-observations.json").write_text(
                json.dumps({"baseline": before, "outcomes": [denied, allowed],
                            "audit": gateway.audit}, indent=2, sort_keys=True) + "\n")
        finally:
            gateway.shutdown()
            worker.join(5)
