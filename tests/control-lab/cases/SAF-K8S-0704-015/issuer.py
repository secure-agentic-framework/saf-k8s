"""Serve fixture-only OIDC discovery and public JWKS on the owned node loopback."""

import json
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ISSUER = "https://127.0.0.1:17443"
ROOT = Path("/issuer")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            body = json.dumps({"issuer": ISSUER, "jwks_uri": ISSUER + "/jwks",
                               "id_token_signing_alg_values_supported": ["RS256"]}).encode()
        elif self.path == "/jwks":
            body = (ROOT / "jwks.json").read_bytes()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


server = HTTPServer(("127.0.0.1", 17443), Handler)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(ROOT / "tls.crt", ROOT / "tls.key")
server.socket = tls.wrap_socket(server.socket, server_side=True)
server.serve_forever()
