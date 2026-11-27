"""Case-local Alertmanager webhook sink; retain only fixture alert identity."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock


messages = []
messages_lock = Lock()
MAX_BODY = 8 * 1024
MAX_MESSAGES = 8
MAX_ALERTS_PER_MESSAGE = 2


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok\n")
            return
        if self.path != "/events":
            self.send_error(404)
            return
        with messages_lock:
            snapshot = list(messages)
        body = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/events":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 0 or length > MAX_BODY:
                self.send_error(413)
                return
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                self.send_error(400)
                return
            alerts = payload.get("alerts", [])
            if not isinstance(alerts, list) or not alerts or len(alerts) > MAX_ALERTS_PER_MESSAGE:
                self.send_error(413)
                return
            rows = []
            for alert in alerts:
                if not isinstance(alert, dict) or not isinstance(alert.get("labels", {}), dict):
                    self.send_error(400)
                    return
                labels = {key: alert.get("labels", {}).get(key) for key in
                          ("alertname", "job", "fixture_target", "severity", "instance",
                           "capture_ref", "capture_phase", "capture_age", "evidence_source",
                           "workload_ref")}
                alert_status = alert.get("status")
                if any(value is not None and (not isinstance(value, str) or len(value) > 160)
                       for value in (alert_status, *labels.values())):
                    self.send_error(413)
                    return
                rows.append({"status": alert_status, "labels": labels})
            receiver = payload.get("receiver")
            message_status = payload.get("status")
            if any(value is not None and (not isinstance(value, str) or len(value) > 160)
                   for value in (receiver, message_status)):
                self.send_error(413)
                return
            message = {"receiver": receiver, "status": message_status, "alerts": rows}
        except (ValueError, TypeError, AttributeError):
            self.send_error(400)
            return
        with messages_lock:
            if len(messages) >= MAX_MESSAGES:
                self.send_error(429)
                return
            messages.append(message)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}\n")

    def log_message(self, _format, *_args):
        pass


ThreadingHTTPServer(("0.0.0.0", 18082), Handler).serve_forever()
