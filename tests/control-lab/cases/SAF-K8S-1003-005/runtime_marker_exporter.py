"""Serve four fixed, inert Prometheus marker series inside the owned cluster."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

BODY = (
    "# TYPE saf_k8s_audit_event gauge\n"
    'saf_k8s_audit_event{event_id="evt-synthetic-privileged-ai-pod",namespace="ai-fixture",verb="create",resource="pods",privileged="true"} 1\n'
    'saf_k8s_audit_event{event_id="evt-synthetic-ai-pod-exec",namespace="ai-fixture",verb="create",resource="pods/exec",privileged="false"} 1\n'
    'saf_k8s_audit_event{event_id="evt-synthetic-safe-ai-pod",namespace="ai-fixture",verb="create",resource="pods",privileged="false"} 1\n'
    'saf_k8s_audit_event{event_id="evt-synthetic-privileged-ai-pod-outside",namespace="system-fixture",verb="create",resource="pods",privileged="true"} 1\n'
).encode()


ALERTS = set()
ROUTES = {"/notify/workload": "workload", "/notify/administration": "administration"}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        route = ROUTES.get(self.path)
        if route is None:
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 16000:
                self.send_error(400)
                return
            request = json.loads(self.rfile.read(length))
            for entry in request["alerts"]:
                labels = entry["labels"]
                fields = ("alertname", "rule_id", "technique_id", "event_id")
                rendered = tuple(labels[field] for field in fields)
                runbook = entry["annotations"]["runbook"]
                ALERTS.add((route, entry["status"], *rendered, runbook))
        except (ValueError, KeyError, TypeError):
            self.send_error(400)
            return
        self.send_response(204)
        self.end_headers()
    def do_GET(self):
        if self.path == "/receipts":
            result = json.dumps(sorted(ALERTS)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(result)))
            self.end_headers()
            self.wfile.write(result)
            return
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
