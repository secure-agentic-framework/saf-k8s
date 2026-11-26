from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

BODY = Path("/fixture/model.json").read_bytes()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/model.json":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *_args):
        return


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
