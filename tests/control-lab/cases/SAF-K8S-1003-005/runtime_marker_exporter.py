"""Serve four fixed, inert Prometheus marker series inside the owned cluster."""
from http.server import BaseHTTPRequestHandler, HTTPServer

BODY = (
    "# TYPE saf_k8s_audit_event gauge\n"
    'saf_k8s_audit_event{event_id="evt-synthetic-privileged-ai-pod",namespace="ai-fixture",verb="create",resource="pods",privileged="true"} 1\n'
    'saf_k8s_audit_event{event_id="evt-synthetic-ai-pod-exec",namespace="ai-fixture",verb="create",resource="pods/exec",privileged="false"} 1\n'
    'saf_k8s_audit_event{event_id="evt-synthetic-safe-ai-pod",namespace="ai-fixture",verb="create",resource="pods",privileged="false"} 1\n'
    'saf_k8s_audit_event{event_id="evt-synthetic-privileged-ai-pod-outside",namespace="system-fixture",verb="create",resource="pods",privileged="true"} 1\n'
).encode()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *_args):
        return


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
