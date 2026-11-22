"""Case-owned HTTPS AdmissionReview fixture for SAF-K8S-0605-007.

Only synthetic ConfigMap requests are handled. A label selects a deliberate
six-second delay; all other requests are permitted. The mutating endpoint adds
one inert metadata label and does not change ConfigMap data.
"""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
import time
from urllib.parse import urlsplit


DELAY_SECONDS = 6


class Handler(BaseHTTPRequestHandler):
    server_version = "saf-fixture"

    def log_message(self, _format, *args):
        # Do not write request bodies, names, or other API data to container logs.
        return

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ("/validate", "/mutate"):
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise ValueError("invalid fixture body length")
            review = json.loads(self.rfile.read(length))
            request = review["request"]
            uid = request["uid"]
            obj = request.get("object") or {}
            labels = obj.get("metadata", {}).get("labels", {})
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self.send_error(400)
            return

        name = obj.get("metadata", {}).get("name", "")
        mode = labels.get("saf-k8s.example/mode")
        if mode == "slow" and name.startswith("saf-0605-") and len(name) <= 64:
            print(f"slow:{path}:{name}", flush=True)
            time.sleep(DELAY_SECONDS)

        response = {"uid": uid, "allowed": mode != "deny"}
        if mode == "deny":
            response["status"] = {"code": 403, "message": f"SAF-0605 fixture explicit denial via {path}"}
        if path == "/mutate" and response["allowed"]:
            response.update({
                "patchType": "JSONPatch",
                "patch": base64.b64encode(json.dumps([
                    {"op": "add",
                     "path": "/metadata/labels/saf-k8s.example~1admission",
                     "value": "fixture"}
                ], separators=(",", ":")).encode()).decode(),
            })
        body = json.dumps({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": response,
        }, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return


server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
