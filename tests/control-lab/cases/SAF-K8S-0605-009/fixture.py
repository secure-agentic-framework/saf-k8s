"""Minimal TLS AdmissionReview server for the synthetic model-reference policy."""
import http.server
import json
import ssl
from urllib.parse import urlsplit


DENIAL = "SAF-0605-009: modelRef models/unreviewed-demo is not approved"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if urlsplit(self.path).path != "/validate":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise ValueError("invalid content length")
            request = json.loads(self.rfile.read(length))["request"]
            obj = request["object"]
            name = obj["metadata"]["name"]
            if (request.get("dryRun") is not True or not name.startswith("synthetic-")
                    or request.get("resource", {}).get("resource") != "inferenceplans"
                    or request.get("namespace") != "saf-0605-009-ai"):
                raise ValueError("outside case scope")
        except (KeyError, TypeError, ValueError):
            self.send_error(400)
            return
        allowed = obj.get("spec", {}).get("modelRef") == "models/approved-v1"
        response = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": request.get("uid", ""),
                "allowed": allowed,
                **({} if allowed else {"status": {
                    "code": 403, "reason": "Forbidden", "message": DENIAL,
                }}),
            },
        }
        # Only fixed probe identity and decision are retained; never log the request body.
        print(json.dumps({
            "event": "admission", "probe": name, "allowed": allowed,
            "response_code": None if allowed else 403,
            "response_reason": None if allowed else "Forbidden",
            "response_message": None if allowed else DENIAL,
        }), flush=True)
        payload = json.dumps(response, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format, *_args):
        return


server = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
