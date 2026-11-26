"""Case-owned HTTPS fixture. It serves only fixed synthetic feed bytes."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl


ROOT = Path("/case")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
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
