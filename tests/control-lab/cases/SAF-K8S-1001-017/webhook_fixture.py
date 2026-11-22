"""Inert HTTPS AdmissionReview server; logs decisions only, never request bodies."""
import http.server
import json
import os
import ssl
from urllib.parse import urlsplit


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if urlsplit(self.path).path != "/validate":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 65536:
                raise ValueError("size")
            request = json.loads(self.rfile.read(length))["request"]
            obj = request["object"]
            metadata = obj["metadata"]
            if (request.get("namespace") != "saf-test" or request.get("operation") != "CREATE"
                    or request.get("resource", {}).get("resource") != "configmaps"
                    or not metadata.get("name", "").startswith("saf-webhook-")
                    or metadata.get("labels", {}).get("saf-lab.audit/fixture") != "true"):
                raise ValueError("scope")
            decision = metadata.get("labels", {}).get("saf-lab.audit/decision")
            if decision not in ("allow", "deny"):
                raise ValueError("decision")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self.send_error(400)
            return
        allowed = decision == "allow"
        response = {
            "apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
            "response": {"uid": request.get("uid", ""), "allowed": allowed,
                         "auditAnnotations": {"decision": decision},
                         **({} if allowed else {"status": {
                             "code": 403, "reason": "Forbidden",
                             "message": "synthetic fixture decision denied"}})},
        }
        print(json.dumps({"probe": metadata["name"], "decision": decision}), flush=True)
        payload = json.dumps(response, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        return


server = http.server.HTTPServer(("0.0.0.0", 8443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(os.environ["TLS_CERT"], os.environ["TLS_KEY"])
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
