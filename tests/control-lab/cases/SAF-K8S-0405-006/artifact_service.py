"""Authorize public test artifact bytes using bounded authenticated attributes."""
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import ssl
import sys
from urllib.request import Request, urlopen

AUDIENCE = "saf-artifact-fixture"
API_TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
API_CA = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
DATA = Path("/fixture/policy.json")
REGISTRY_CURRENT = "fixture-attribute-current"
REGISTRY_VERSIONS = {"fixture-attribute-v1", "fixture-attribute-v2"}
API_BASE = "https://kubernetes.default.svc/api/v1/namespaces/saf-test/configmaps/"


def identify(token):
    review = {
        "apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
        "spec": {"token": token, "audiences": [AUDIENCE]},
    }
    req = Request("https://kubernetes.default.svc/apis/authentication.k8s.io/v1/tokenreviews",
                  data=json.dumps(review).encode(), headers={
                      "Content-Type": "application/json",
                      "Authorization": "Bearer " + API_TOKEN.read_text().strip(),
                  })
    ca = ssl.create_default_context(cafile=str(API_CA))
    with urlopen(req, context=ca, timeout=5) as response:
        status = json.load(response)["status"]
    if status.get("authenticated") and AUDIENCE in status.get("audiences", []):
        return status["user"]["username"]
    return None


def api_request(path, *, method="GET", body=None):
    headers = {"Authorization": "Bearer " + API_TOKEN.read_text().strip()}
    encoded = None
    if body is not None:
        encoded = json.dumps(body, sort_keys=True).encode()
        headers["Content-Type"] = "application/merge-patch+json" if method == "PATCH" else "application/json"
    req = Request(API_BASE + path, data=encoded, headers=headers, method=method)
    ca = ssl.create_default_context(cafile=str(API_CA))
    with urlopen(req, context=ca, timeout=5) as response:
        payload = response.read()
        return response.status, json.loads(payload) if payload else {}


def current_policy():
    _, pointer = api_request(REGISTRY_CURRENT)
    name = pointer.get("data", {}).get("policyName")
    if name not in REGISTRY_VERSIONS:
        raise ValueError("unrecognized fixture attribute version")
    _, record = api_request(name)
    if record.get("immutable") is not True:
        raise ValueError("fixture attribute version is not immutable")
    return json.loads(record.get("data", {})["policy.json"])


def update_registry(version):
    targets = {"v1": "fixture-attribute-v1", "v2": "fixture-attribute-v2"}
    target = targets.get(version)
    if target is None:
        print(json.dumps({"status": 400, "changed": False}))
        return
    try:
        status, _ = api_request(REGISTRY_CURRENT, method="PATCH",
                                body={"data": {"policyName": target, "version": version}})
        changed = status == 200
    except Exception as error:
        # Kubernetes error bodies and authorization tokens are deliberately
        # not emitted to process output or retained evidence.
        from urllib.error import HTTPError
        status = error.code if isinstance(error, HTTPError) else 0
        changed = False
    print(json.dumps({"status": status, "changed": changed}, sort_keys=True))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            self.answer(401, "identity-required")
            return
        try:
            subject = identify(header.removeprefix("Bearer "))
        except (OSError, ValueError, KeyError):
            self.answer(503, "identity-authority-unavailable")
            return
        data = self.server.data
        if self.server.enforce:
            try:
                data = current_policy()
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                self.answer(503, "attribute-authority-unavailable")
                return
        if subject not in data["subjects"]:
            self.answer(401, "identity-untrusted")
            return
        artifact = data["artifacts"].get(self.path.removeprefix("/artifact/"))
        if not artifact:
            self.answer(404, "fixture-artifact-unavailable")
            return
        if self.server.enforce:
            attributes = data["subjects"].get(subject)
            if attributes is None:
                self.answer(401, "identity-untrusted")
                return
            for field in ("classification", "sensitivity", "environment"):
                if artifact[field] not in attributes[field]:
                    self.answer(403, field)
                    return
        self.answer(200, "approved", artifact["content"])

    def answer(self, status, decision, marker=None):
        body = json.dumps({"decision": decision, "marker": marker}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def serve(mode):
    server = HTTPServer(("0.0.0.0", 8443), Handler)
    server.data = json.loads(DATA.read_text())
    server.enforce = mode == "enforced"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/certificate/tls.crt", "/certificate/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def probe(host, item):
    context = ssl.create_default_context(cafile="/trust/ca.crt")
    client = HTTPSConnection(host, 8443, context=context, timeout=7)
    try:
        token = Path("/identity/token").read_text().strip()
        client.request("GET", "/artifact/" + item, headers={"Authorization": "Bearer " + token})
        response = client.getresponse()
        print(json.dumps({"status": response.status, **json.loads(response.read())}))
    finally:
        client.close()


if sys.argv[1] == "server":
    serve(sys.argv[2])
elif sys.argv[1] == "registry-write":
    update_registry(sys.argv[2] if len(sys.argv) > 2 else "")
else:
    probe(*sys.argv[2:])
