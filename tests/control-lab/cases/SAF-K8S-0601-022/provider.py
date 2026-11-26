"""Serve only the case's synthetic registry config and a fixed denied key."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import ssl

SOURCE = Path("/data")
OBSERVATIONS = Path("/evidence/provider-access.jsonl")


class Provider(BaseHTTPRequestHandler):
    def _record(self, status):
        row = {"path": self.path, "status": status}
        with OBSERVATIONS.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, sort_keys=True) + "\n")

    def do_GET(self):
        if self.path == "/denied-registry-auth":
            self._record(403)
            self.send_error(403)
            return
        if self.path != "/fixture-registry-auth":
            self._record(404)
            self.send_error(404)
            return
        self._record(200)
        response = json.dumps({"value": (SOURCE / "registry-config.json").read_text(encoding="utf-8")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_args):
        return


api = HTTPServer(("0.0.0.0", 9443), Provider)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
api.socket = tls.wrap_socket(api.socket, server_side=True)
api.serve_forever()
