"""Emit a single synthetic metric over the fixture's authenticated HTTPS endpoint."""
import base64
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import ssl

password = Path("/auth/password").read_bytes().strip()
expected = "Basic " + base64.b64encode(b"saf-synthetic-scraper:" + password).decode()
sample = b'# TYPE saf_fixture_metric gauge\nsaf_fixture_metric{fixture="1002-001",workload="synthetic"} 42\n'


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404)
            return
        if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), expected.encode()):
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Basic realm=fixture-exporter")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(sample)))
        self.end_headers()
        self.wfile.write(sample)

    def log_message(self, *_args):
        return


server = HTTPServer(("0.0.0.0", 9108), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
