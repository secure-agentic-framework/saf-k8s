"""Serve public fixture markers from a separate HTTPS secret-provider API."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import ssl

SOURCE = Path("/source")


class Provider(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/fixture-value":
            self.send_error(404)
            return
        if (SOURCE / "available").read_text() != "yes":
            self.send_error(503)
            return
        response = json.dumps({"value": (SOURCE / "value").read_text()}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *args):
        return


api = HTTPServer(("0.0.0.0", 9443), Provider)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
api.socket = tls.wrap_socket(api.socket, server_side=True)
api.serve_forever()
