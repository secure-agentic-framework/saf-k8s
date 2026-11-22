"""Owned loopback-only synthetic application and event collector."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from urllib.request import Request, urlopen


MODEL = {"name": "fictional-model-alpha", "version": "0.0.0-fixture"}
SYNTHETIC_PROMPT = "SYNTHETIC_ONLY_NO_REAL_DATA_1001_007"
MAX_BODY = 1024


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _handler(do_post):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            # Avoid default HTTP server access logs, which can expose request data.
            return

        def do_POST(self):
            if self.client_address[0] not in ("127.0.0.1", "::1"):
                self.send_error(403)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_BODY:
                    self.send_error(413)
                    return
                request = json.loads(self.rfile.read(length))
            except (ValueError, json.JSONDecodeError):
                self.send_error(400)
                return
            status, response = do_post(self.path, request)
            body = json.dumps(response, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


class ScopedCollector:
    """Accept fixed-shape, payload-free events from loopback only."""
    def __init__(self, record_path):
        self.record_path = record_path
        self.records = []
        self.lock = threading.Lock()
        self.server = _Server(("127.0.0.1", 0), _handler(self._receive))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}/collect"

    def start(self):
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _receive(self, path, event):
        allowed = {"event_id", "event_type", "model", "model_version", "outcome"}
        if path != "/collect" or set(event) != allowed:
            return 400, {"accepted": False}
        if (event.get("event_type") != "inference_completed"
                or event.get("model") != MODEL["name"]
                or event.get("model_version") != MODEL["version"]
                or event.get("outcome") != "synthetic-success"
                or not str(event.get("event_id", "")).startswith("saf-k8s-1001-007-")):
            return 400, {"accepted": False}
        clean = dict(event)
        encoded = json.dumps(clean, separators=(",", ":"))
        with self.lock:
            if len(self.records) >= 4:
                return 429, {"accepted": False}
            with self.record_path.open("a", encoding="utf-8") as out:
                out.write(encoded + "\n")
            self.records.append(clean)
        return 202, {"accepted": True}


class SyntheticApplication:
    """Accept one inert synthetic prompt; emit a minimal event to loopback."""
    def __init__(self, collector_url):
        self.collector_url = collector_url
        self.server = _Server(("127.0.0.1", 0), _handler(self._infer))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}/infer"

    def start(self):
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _infer(self, path, request):
        if (path != "/infer" or set(request) != {"prompt", "event_id"}
                or request.get("prompt") != SYNTHETIC_PROMPT):
            return 400, {"accepted": False}
        event_id = str(request.get("event_id", ""))
        if not event_id.startswith("saf-k8s-1001-007-"):
            return 400, {"accepted": False}
        # The request body is deliberately not copied into the event or response.
        event = {
            "event_id": event_id,
            "event_type": "inference_completed",
            "model": MODEL["name"],
            "model_version": MODEL["version"],
            "outcome": "synthetic-success",
        }
        if self.collector_url is None:
            return 200, {"accepted": True, "event_id": event_id}
        try:
            data = json.dumps(event, separators=(",", ":")).encode()
            req = Request(self.collector_url, data=data,
                          headers={"Content-Type": "application/json"}, method="POST")
            with urlopen(req, timeout=2) as response:
                accepted = response.status == 202
        except Exception:
            accepted = False
        return (200 if accepted else 503), {"accepted": accepted, "event_id": event_id}


def post_synthetic_request(url, event_id):
    body = json.dumps({"prompt": SYNTHETIC_PROMPT, "event_id": event_id}).encode()
    request = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=2) as response:
        result = json.loads(response.read(MAX_BODY))
        return response.status, result
