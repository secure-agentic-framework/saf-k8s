"""Owned fixed-marker HTTP/1.1 endpoint used only by the connection-lifecycle fixture."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path not in ("/allow", "/other"):
            self.send_error(404)
            return
        body = b"saf-identity-marker\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        # Access evidence is obtained from the destination Envoy, not application logs.
        return


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
