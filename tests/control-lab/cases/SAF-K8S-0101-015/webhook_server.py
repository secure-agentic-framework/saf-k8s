"""Synthetic mTLS SubjectAccessReview endpoint for SAF-K8S-0101-015."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
from urllib.parse import urlsplit


IDENTITY = "system:serviceaccount:saf-test:webhook-probe"
NAMESPACE = "saf-test"
RESOURCE = "configmaps"
RESOURCE_NAME = "webhook-probe"


class Handler(BaseHTTPRequestHandler):
    server_version = "SAFWebhook/1"

    def log_message(self, *_args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 65536:
            self.send_error(413)
            return
        try:
            review = json.loads(self.rfile.read(length))
        except (ValueError, TypeError):
            self.send_error(400)
            return
        spec = review.get("spec", {})
        attrs = spec.get("resourceAttributes", {})
        cert = self.connection.getpeercert()
        subject = dict(item for group in cert.get("subject", ()) for item in group)
        client_cn = subject.get("commonName", "")
        endpoint = urlsplit(self.path).path
        fields = {
            "path": endpoint == "/authorize",
            "version": review.get("apiVersion") == "authorization.k8s.io/v1",
            "kind": review.get("kind") == "SubjectAccessReview",
            "user": spec.get("user") == IDENTITY,
            "verb": attrs.get("verb") == "get",
            "group": attrs.get("group", "") == "",
            "resource": attrs.get("resource") == RESOURCE,
            "subresource": attrs.get("subresource", "") == "",
            "namespace": attrs.get("namespace") == NAMESPACE,
            "name": attrs.get("name") == RESOURCE_NAME,
            "client_certificate": client_cn == "saf-apiserver",
        }
        exact = all(fields.values())
        # Emit only fixed, synthetic fields. Never log the body, token, or keys.
        if exact:
            print(json.dumps({"event": "sar", "client_cn": "saf-apiserver",
                              "identity": IDENTITY, "verb": "get", "resource": RESOURCE,
                              "namespace": NAMESPACE, "name": RESOURCE_NAME, "allowed": True}),
                  flush=True)
        else:
            print(json.dumps({"event": "unexpected-sar",
                              "mismatched_fields": [key for key, value in fields.items() if not value],
                              "path_class": endpoint if endpoint in ("/", "/authorize/") else "other"}),
                  flush=True)
        payload = {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SubjectAccessReview",
            "status": {"allowed": exact, "reason": "synthetic exact-read policy" if exact
                       else "outside synthetic exact-read policy"},
        }
        encoded = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)


context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain("/case/server.crt", "/case/server.key")
context.load_verify_locations(cafile="/case/ca.crt")
context.verify_mode = ssl.CERT_REQUIRED


class WebhookServer(ThreadingHTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(4)
        try:
            return context.wrap_socket(connection, server_side=True), address
        except OSError as error:
            connection.close()
            if getattr(error, "reason", None) in {
                "TLSV1_ALERT_UNKNOWN_CA", "SSLV3_ALERT_BAD_CERTIFICATE",
            }:
                print('{"event":"client-rejected-server-cert"}', flush=True)
            raise


server = WebhookServer(("0.0.0.0", 9443), Handler)
print('{"event":"ready"}', flush=True)
server.serve_forever()
