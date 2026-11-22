"""TLS-protected test-only inference models, router and fixed clients."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import socket
import ssl
import sys


AUDIENCE = "urn:saf:route:"
EXPECTED = "synthetic-v2"
ROUTER_NAME = "router.saf-inference.test"
MODEL = "saf-fixture-model"
SCENARIOS = {"initial", "denied-primary", "failover", "denied-peer", "stale", "recovered"}


def identity(socket):
    parts = socket.getpeercert().get("subjectAltName", ())
    return next((value for kind, value in parts if kind == "URI"), "")


def secure_client(host, port, server_name, path, cert_dir, headers, timeout=2):
    context = ssl.create_default_context(cafile=f"{cert_dir}/ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(f"{cert_dir}/tls.crt", f"{cert_dir}/tls.key")

    class VerifiedHTTP(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
            self.sock = self._context.wrap_socket(raw, server_hostname=server_name)

    connection = VerifiedHTTP(host, port, timeout=timeout, context=context)
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read(512))
    finally:
        connection.close()


class JsonHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, value):
        data = json.dumps(value, sort_keys=True).encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def fixture_event(self):
        value = self.headers.get("X-Fixture-Event")
        return value if value in SCENARIOS else None


class ModelHandler(JsonHandler):
    def do_GET(self):
        event = self.fixture_event()
        if identity(self.connection) != AUDIENCE + "router" or not event:
            self.reply(403, {"result": "not-authorized"})
            return
        version = os.environ["MODEL_REVISION"]
        if self.path == "/status":
            result = {"model": MODEL, "revision": version}
        elif self.path == "/infer" and self.headers.get("If-Match") == version:
            result = {"model": MODEL, "revision": version,
                      "marker": os.environ["MODEL_MARKER"]}
        else:
            self.reply(412, {"result": "model-pin-required"})
            return
        receipt = {"event": event, "path": self.path, "revision": version,
                   "router_identity_authenticated": True}
        print(json.dumps(receipt, sort_keys=True), flush=True)
        self.reply(200, result)


class RouterHandler(JsonHandler):
    def do_GET(self):
        event = self.fixture_event()
        if not event or self.path != "/infer":
            self.reply(404, {"result": "unknown-fixture"})
            return
        if identity(self.connection) != AUDIENCE + "eligible-client":
            self.reply(403, {"result": "model-not-authorized"})
            return
        outcomes = {}
        for name in ("primary", "peer"):
            if name == "primary":
                host = "model-primary.saf-test.svc.cluster.local"
                port = 8443
            else:
                host = os.environ["PEER_IP"]
                port = int(os.environ["PEER_PORT"])
            headers = {"X-Fixture-Event": event}
            try:
                proof, status = secure_client(host, port, f"{name}.saf-inference.test",
                                              "/status", "/tls", headers)
                if proof != 200 or status != {"model": MODEL, "revision": EXPECTED}:
                    outcomes[name] = "stale-or-unverified"
                    continue
                code, result = secure_client(host, port, f"{name}.saf-inference.test",
                                             "/infer", "/tls",
                                             {**headers, "If-Match": EXPECTED})
            except (OSError, ValueError, http.client.HTTPException):
                outcomes[name] = "unavailable"
                continue
            if code != 200 or result.get("revision") != EXPECTED or result.get("model") != MODEL:
                outcomes[name] = "stale-or-unverified"
                continue
            self.reply(200, {"route": name, **result})
            return
        self.reply(503, {"result": "no-eligible-model", "outcomes": outcomes})


def listen(handler):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile="/tls/ca.crt")
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    context.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingHTTPServer(("0.0.0.0", 8443), handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "backend":
        listen(ModelHandler)
    elif mode == "router":
        listen(RouterHandler)
    elif mode == "probe" and sys.argv[2] in SCENARIOS:
        event = sys.argv[2]
        principal = "unassigned" if event.startswith("denied-") else "eligible"
        status, result = secure_client("inference-router.saf-test.svc.cluster.local", 8443,
                                       ROUTER_NAME, "/infer", f"/{principal}",
                                       {"X-Fixture-Event": event}, timeout=9)
        print(json.dumps({"status": status, "result": result}, sort_keys=True))
    else:
        raise SystemExit("Invalid fixed fixture mode")
