"""Case-owned HTTPS fixture. It serves only fixed synthetic feed bytes."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
from pathlib import Path
import ssl


ROOT = Path("/case")
RECOVERY_REQUESTS = 0


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global RECOVERY_REQUESTS
        if self.path in ("/ready", "/unavailable", "/recover"):
            expected = Path("/auth/token").read_text().strip().encode()
            supplied = self.headers.get("Authorization", "").encode()
            if not hmac.compare_digest(supplied, b"Bearer " + expected):
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/ready":
                body = (ROOT / "approved-bundle.json").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/recover":
                RECOVERY_REQUESTS += 1
                if RECOVERY_REQUESTS == 1:
                    self.send_response(503)
                    self.send_header("Retry-After", "1")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if RECOVERY_REQUESTS == 2:
                    body = (ROOT / "approved-bundle.json").read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(429)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(503)
            self.send_header("Retry-After", "30")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        assets = {"/approved": "approved-bundle.json", "/modified": "damaged-bundle.json"}
        name = assets.get(self.path)
        if name is None:
            self.send_error(404)
            return
        body = (ROOT / name).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        # Avoid request logging; the only output is the client's sanitized result.
        return


server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
