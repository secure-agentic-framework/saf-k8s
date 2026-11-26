"""Serve only public discovery data and a public JWKS inside the fixture node."""
import json
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
ISSUER = "https://127.0.0.1:17443"


class IssuerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            content = json.dumps({"issuer": ISSUER, "jwks_uri": ISSUER + "/jwks",
                                  "id_token_signing_alg_values_supported": ["RS256"]}).encode()
        elif self.path == "/jwks":
            content = (HERE / "jwks.json").read_bytes()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, *args):
        return


server = HTTPServer(("127.0.0.1", 17443), IssuerHandler)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(HERE / "tls.crt", HERE / "tls.key")
server.socket = tls.wrap_socket(server.socket, server_side=True)
server.serve_forever()
