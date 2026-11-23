"""Owned fixed-data feature-store gateway fixture for the SAF Kind case."""
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

NS = "saf-test"
AUDIENCE = "saf-feature-store"
READER = f"system:serviceaccount:{NS}:fixture-feature-reader"
PORT = 8443
GROUPS = {"fixture-customer-profile", "fixture-device-health"}
STORES = {"online", "offline"}
SERVICE_IDENTITY = Path("/var/run/secrets/kubernetes.io/serviceaccount")


def api_request(path, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        "https://kubernetes.default.svc" + path,
        data,
        {"Authorization": "Bearer " + (SERVICE_IDENTITY / "token").read_text().strip(),
         "Content-Type": "application/json"},
    )
    context = ssl.create_default_context(cafile=str(SERVICE_IDENTITY / "ca.crt"))
    with urllib.request.urlopen(request, context=context, timeout=5) as response:
        return json.load(response)


def backend(group, store):
    item = api_request(f"/api/v1/namespaces/{NS}/configmaps/{group}-{store}")
    return json.loads(item["data"]["feature.json"])


def token_review(token):
    if not token:
        return None
    try:
        review = api_request("/apis/authentication.k8s.io/v1/tokenreviews", {
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenReview",
            "spec": {"token": token, "audiences": [AUDIENCE]},
        })
        status = review["status"]
    except (OSError, ValueError, KeyError):
        return None
    if status.get("authenticated") is not True or AUDIENCE not in status.get("audiences", []):
        return None
    return status.get("user", {}).get("username")


class Handler(BaseHTTPRequestHandler):
    server_version = "fixture-store/1"
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        return

    def respond(self, status, payload):
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def note(self, principal, group, store, decision):
        row = {"event": "feature-read", "principal": principal, "group": group,
               "store": store, "decision": decision}
        print(json.dumps(row, sort_keys=True, separators=(",", ":")), flush=True)

    def do_GET(self):
        if self.path == "/ready":
            self.respond(200, {"ready": True})
        else:
            self.respond(404, {"status": 404, "decision": "not-found"})

    def do_POST(self):
        if self.path != "/read":
            self.respond(404, {"status": 404, "decision": "not-found"})
            return
        size = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(size))
        auth = self.headers.get("Authorization", "")
        principal = token_review(auth[7:] if auth.startswith("Bearer ") else "")
        if principal != READER:
            self.note("unverified", request.get("group"), request.get("store"), "unauthenticated")
            self.respond(401, {"status": 401, "decision": "unauthenticated", "result": None})
            return
        group = request.get("group")
        store = request.get("store")
        version = request.get("version")
        if group not in GROUPS or store not in STORES:
            self.respond(400, {"status": 400, "decision": "invalid-request", "result": None})
            return
        permitted = self.server.mode == "baseline" or group == "fixture-customer-profile"
        if not permitted:
            self.note("fixture-reader", group, store, "denied")
            self.respond(403, {"status": 403, "decision": "denied", "result": None})
            return
        try:
            definition = backend(group, store)
        except (OSError, ValueError, KeyError):
            self.note("fixture-reader", group, store, "backend-unavailable")
            self.respond(503, {"status": 503, "decision": "backend-unavailable", "result": None})
            return
        if version != definition["definition_version"]:
            self.note("fixture-reader", group, store, "version-not-found")
            self.respond(404, {"status": 404, "decision": "version-not-found", "result": None})
            return
        self.note("fixture-reader", group, store, "allowed")
        self.respond(200, {"status": 200, "decision": "allowed", "group": group,
                           "store": store, "definition_version": version,
                           "result": definition["result"]})


def serve(mode):
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.mode = mode
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/certificate/tls.crt", "/certificate/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(json.dumps({"event": "fixture-ready", "mode": mode}, sort_keys=True), flush=True)
    server.serve_forever()


def probe(host, group, store, version, credential="token"):
    token_path = "/identity/token"
    headers = {"Content-Type": "application/json"}
    if credential == "token":
        headers["Authorization"] = "Bearer " + open(token_path).read().strip()
    request = urllib.request.Request("https://" + host + ":8443/read",
                                     json.dumps({"group": group, "store": store,
                                                 "version": version}).encode(), headers,
                                     method="POST")
    context = ssl.create_default_context(cafile="/trust/ca.crt")
    try:
        with urllib.request.urlopen(request, context=context, timeout=8) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def wait_for_service(host):
    context = ssl.create_default_context(cafile="/trust/ca.crt")
    deadline = time.monotonic() + 20
    while True:
        try:
            with urllib.request.urlopen(f"https://{host}:{PORT}/ready", context=context,
                                        timeout=3) as response:
                assert json.load(response) == {"ready": True}
                return
        except (urllib.error.URLError, TimeoutError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(sys.argv[2])
    elif sys.argv[1] == "ready":
        wait_for_service(sys.argv[2])
    elif sys.argv[1] == "probe":
        code, payload = probe(*sys.argv[2:])
        print(json.dumps({"http_status": code, "body": payload}, sort_keys=True))
    elif sys.argv[1] == "backend":
        try:
            backend(*sys.argv[2:])
        except urllib.error.HTTPError as error:
            print(error.code)
        else:
            print(200)
