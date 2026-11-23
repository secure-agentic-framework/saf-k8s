"""A fixed HTTPS admission handler for the case-owned inert custom resource."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import ssl
from urllib.parse import urlsplit

GROUP = "availability.saf-fixture.example.test"


class Admission(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def send(self, status, data):
        payload = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self.send(200 if self.path == "/healthz" else 404, {})

    def do_POST(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if urlsplit(self.path).path != "/validate" or not 0 < size <= 65536:
                raise ValueError("unexpected fixture request")
            review = json.loads(self.rfile.read(size))
            entry = review["request"]
            name = entry["object"]["metadata"]["name"]
            resource = entry["resource"]
            if (entry["namespace"] != "saf-test" or entry["operation"] != "CREATE"
                    or entry.get("dryRun") is not True or resource != {
                        "group": GROUP, "version": "v1", "resource": "checks"
                    } or not name.startswith("saf-reliability-")):
                raise ValueError("outside fixture scope")
            allowed = entry["object"]["spec"]["enabled"] is True
            response = {"uid": entry["uid"], "allowed": allowed}
            if not allowed:
                response["status"] = {"code": 422, "reason": "Invalid",
                                      "message": "the selected fixture field is disabled"}
        except (KeyError, ValueError, TypeError) as error:
            print(json.dumps({"fixture_validation_error": str(error)}), flush=True)
            self.send(400, {})
            return
        print(json.dumps({"probe": name, "allowed": allowed, "pod_uid": os.environ["POD_UID"]}), flush=True)
        self.send(200, {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "response": response})


def run():
    with ThreadingHTTPServer(("0.0.0.0", 8443), Admission) as server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.serve_forever()


if __name__ == "__main__":
    run()
