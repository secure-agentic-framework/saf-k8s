"""Fixed loopback-only circuit-breaker reference workload for an owned Job."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time
import urllib.error
import urllib.request

THRESHOLD = 2
COOLDOWN_SECONDS = 0.16
PROBE_HOLD_SECONDS = 0.8


class BackendState:
    def __init__(self):
        self.lock = threading.Lock()
        self.calls = 0
        self.statuses = []
        self.probe_started = threading.Event()
        self.release_probe = threading.Event()

    def next_response(self):
        with self.lock:
            self.calls += 1
            call = self.calls
            status = 503 if call <= THRESHOLD else 200
            self.statuses.append(status)
        if call == THRESHOLD + 1:
            self.probe_started.set()
            self.release_probe.wait(PROBE_HOLD_SECONDS)
        return call, status

    def snapshot(self):
        with self.lock:
            return self.calls, list(self.statuses)


class BackendHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/fixed-inference":
            self._send(404, {"reason": "not_found"})
            return
        call, status = self.server.backend.next_response()
        reason = "fixture_unavailable" if status == 503 else "fixture_healthy"
        self._send(status, {"call": call, "reason": reason})

    def _send(self, status, value):
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class CircuitBreakerReference:
    """Small thread-safe reference state machine, not production middleware."""

    def __init__(self, backend_url):
        self.backend_url = backend_url
        self.lock = threading.Lock()
        self.state = "closed"
        self.consecutive_failures = 0
        self.open_until = 0.0
        self.half_open_probe_in_flight = False
        self.half_open_probes = 0
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self):
        now = time.monotonic()
        with self.lock:
            if self.state == "open":
                if now < self.open_until:
                    return {"status": 503, "reason": "breaker_open",
                            "backend_called": False, "state": "open"}
                self.state = "half_open"
            was_probe = self.state == "half_open"
            if was_probe:
                if self.half_open_probe_in_flight:
                    return {"status": 503, "reason": "half_open_probe_in_progress",
                            "backend_called": False, "state": "half_open"}
                self.half_open_probe_in_flight = True
                self.half_open_probes += 1

        try:
            with self.opener.open(self.backend_url, timeout=1.0) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
        except (OSError, TimeoutError, urllib.error.URLError):
            status = 502

        with self.lock:
            if status >= 500:
                if was_probe:
                    self.state = "open"
                    self.open_until = time.monotonic() + COOLDOWN_SECONDS
                    self.half_open_probe_in_flight = False
                else:
                    self.consecutive_failures += 1
                    if self.consecutive_failures >= THRESHOLD:
                        self.state = "open"
                        self.open_until = time.monotonic() + COOLDOWN_SECONDS
            else:
                self.state = "closed"
                self.consecutive_failures = 0
                self.open_until = 0.0
                self.half_open_probe_in_flight = False
            return {"status": status,
                    "reason": "backend_failure" if status >= 500 else "backend_success",
                    "backend_called": True, "state": self.state}


def execute():
    backend = BackendState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), BackendHandler)
    server.daemon_threads = True
    server.backend = backend
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    breaker = CircuitBreakerReference(
        f"http://127.0.0.1:{server.server_address[1]}/fixed-inference")
    result = {}
    probe_thread = None
    probe_results = []
    probe_errors = []

    try:
        result["first_failure"] = breaker.call()
        count, statuses = backend.snapshot()
        result["first_failure"].update({"backend_calls": count, "backend_statuses": statuses})

        result["threshold_failure"] = breaker.call()
        count, statuses = backend.snapshot()
        result["threshold_failure"].update({"backend_calls": count, "backend_statuses": statuses})

        result["open_rejection"] = breaker.call()
        count, statuses = backend.snapshot()
        result["open_rejection"].update({"backend_calls": count, "backend_statuses": statuses})

        time.sleep(COOLDOWN_SECONDS + 0.03)

        def half_open_call():
            try:
                probe_results.append(breaker.call())
            except Exception as error:
                probe_errors.append(type(error).__name__)

        probe_thread = threading.Thread(target=half_open_call, daemon=True)
        probe_thread.start()
        probe_started = backend.probe_started.wait(timeout=1.0)
        count, statuses = backend.snapshot()
        result["half_open_in_flight"] = {
            "probe_started": probe_started,
            "backend_calls": count,
            "backend_statuses": statuses,
            "half_open_probe_count": breaker.half_open_probes,
        }
        result["competing_half_open_request"] = breaker.call()
        count, statuses = backend.snapshot()
        result["competing_half_open_request"].update(
            {"backend_calls": count, "backend_statuses": statuses})

        backend.release_probe.set()
        probe_thread.join(timeout=2.0)
        result["half_open_probe"] = probe_results[0] if len(probe_results) == 1 else {
            "status": 0, "reason": "probe_missing", "backend_called": False,
            "state": breaker.state}
        count, statuses = backend.snapshot()
        result["half_open_probe"].update(
            {"backend_calls": count, "backend_statuses": statuses,
             "half_open_probe_count": breaker.half_open_probes})

        result["recovered_request"] = breaker.call()
        count, statuses = backend.snapshot()
        result["recovered_request"].update(
            {"backend_calls": count, "backend_statuses": statuses})

        count, statuses = backend.snapshot()
        with open(__file__, "rb") as source_file:
            source_sha = hashlib.sha256(source_file.read()).hexdigest()
        return {
            "source_sha256": source_sha,
            "backend_calls": count,
            "backend_sequence": statuses,
            "failure_threshold": THRESHOLD,
            "cooldown_ms": int(COOLDOWN_SECONDS * 1000),
            "observations": result,
            "probe_errors": probe_errors,
            "probe_thread_stopped": probe_thread is None or not probe_thread.is_alive(),
        }
    finally:
        backend.release_probe.set()
        if probe_thread is not None:
            probe_thread.join(timeout=2.0)
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2.0)


if __name__ == "__main__":
    print(json.dumps(execute(), sort_keys=True, separators=(",", ":")))
