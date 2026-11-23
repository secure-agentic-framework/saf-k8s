"""Serve three fixed, public telemetry fixtures inside the test namespace."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SAMPLES = {"normal": 0.2, "high": 0.95, "missing": None}


class Exporter(BaseHTTPRequestHandler):
    def do_GET(self):
        target = self.path.removeprefix("/")
        if target not in SAMPLES:
            self.send_error(404)
            return
        rows = ["# TYPE fixture_exporter_info gauge", "fixture_exporter_info 1"]
        sample = SAMPLES[target]
        if sample is not None:
            rows.extend(("# TYPE fixture_gpu_utilization_ratio gauge", f"fixture_gpu_utilization_ratio {sample}"))
        payload = ("\n".join(rows) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format, *_args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8080), Exporter).serve_forever()
