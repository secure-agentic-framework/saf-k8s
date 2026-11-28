"""Serve one healthy synthetic source and one deliberately failing scrape path."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/healthy", "/zero"):
            value = "0.2" if self.path == "/healthy" else "0"
            body = (f"# TYPE fixture_gpu_utilization_ratio gauge\n"
                    f"fixture_gpu_utilization_ratio {value}\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/failed":
            self.send_error(503, "synthetic fixture scrape failure")
            return
        self.send_error(404)
    def log_message(self, *_args):
        pass

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
