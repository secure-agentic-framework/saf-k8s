"""Owned inert HTTP worker with tiny cooperative monotonic deadline checks."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib
import json
import time


MAX_UNITS = 8
UNIT_DELAY_SECONDS = 0.015
MAX_DEADLINE_MS = 300
ALLOWED_SESSIONS = {"session-expiring", "session-allowed"}


class Engine:
    def __init__(self):
        self.counters = {
            "accepted_requests": 0,
            "request_deadline_stops": 0,
            "session_deadline_stops": 0,
            "batch_deadline_stops": 0,
            "work_units_completed": 0,
            "work_units_by_scope": {"request": 0, "session": 0, "batch": 0},
        }
        self.sessions = {}

    @staticmethod
    def _bounded_unit(unit_index):
        value = f"inert-fixture-unit-{unit_index}".encode("ascii")
        for _ in range(64):
            value = hashlib.sha256(value).digest()
        time.sleep(UNIT_DELAY_SECONDS)
        return value[0]

    def work(self, request):
        scope = request.get("scope")
        units = request.get("units")
        if scope not in {"request", "session", "batch"}:
            return 400, {"accepted": False, "reason": "invalid_scope"}
        if type(units) is not int or not 1 <= units <= MAX_UNITS:
            return 400, {"accepted": False, "reason": "invalid_unit_count"}

        session = None
        if scope == "request":
            deadline_ms = request.get("deadline_ms")
            if type(deadline_ms) is not int or not 20 <= deadline_ms <= MAX_DEADLINE_MS:
                return 400, {"accepted": False, "reason": "invalid_deadline"}
        elif scope == "batch":
            deadline_ms = request.get("deadline_ms")
            if type(deadline_ms) is not int or not 20 <= deadline_ms <= MAX_DEADLINE_MS:
                return 400, {"accepted": False, "reason": "invalid_deadline"}
        else:
            session_id = request.get("session_id")
            if session_id not in ALLOWED_SESSIONS:
                return 400, {"accepted": False, "reason": "invalid_session"}
            session = self.sessions.get(session_id)
            if session is None:
                deadline_ms = request.get("deadline_ms")
                if type(deadline_ms) is not int or not 20 <= deadline_ms <= MAX_DEADLINE_MS:
                    return 400, {"accepted": False, "reason": "invalid_deadline"}
                now = time.monotonic()
                session = {"started_at": now,
                           "deadline_at": now + deadline_ms / 1000.0,
                           "deadline_ms": deadline_ms,
                           "units_completed": 0}
                self.sessions[session_id] = session
            elif "deadline_ms" in request:
                return 400, {"accepted": False, "reason": "session_deadline_is_immutable"}

        started = time.monotonic()
        if scope == "session":
            deadline_at = session["deadline_at"]
            deadline_ms = session["deadline_ms"]
        else:
            deadline_at = started + deadline_ms / 1000.0
        units_completed = 0
        stopped = False
        for index in range(units):
            if time.monotonic() >= deadline_at:
                stopped = True
                break
            self._bounded_unit(index)
            units_completed += 1
            self.counters["work_units_completed"] += 1
            self.counters["work_units_by_scope"][scope] += 1
            if session is not None:
                session["units_completed"] += 1

        elapsed_ms = (time.monotonic() - started) * 1000.0
        if stopped:
            self.counters[f"{scope}_deadline_stops"] += 1
        else:
            self.counters["accepted_requests"] += 1
        if scope == "session":
            scope_elapsed_ms = (time.monotonic() - session["started_at"]) * 1000.0
        else:
            scope_elapsed_ms = elapsed_ms
        status = 504 if stopped or units_completed != units else 200
        return status, {
            "scope": scope,
            "status": status,
            "deadline_ms": deadline_ms,
            "elapsed_ms": round(elapsed_ms, 3),
            "scope_elapsed_ms": round(scope_elapsed_ms, 3),
            "units_requested": units,
            "units_completed": units_completed,
            "deadline_stop": stopped,
        }


ENGINE = Engine()


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, payload):
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ready": True, "fixture": "bounded-deadline-worker-v1"})
        elif self.path == "/__fixture/state":
            self._send(200, {"counters": ENGINE.counters})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/work":
            self._send(404, {"accepted": False, "reason": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(400, {"accepted": False, "reason": "invalid_length"})
            return
        if not 1 <= length <= 512:
            self._send(400, {"accepted": False, "reason": "invalid_length"})
            return
        try:
            request = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send(400, {"accepted": False, "reason": "invalid_json"})
            return
        if not isinstance(request, dict):
            self._send(400, {"accepted": False, "reason": "invalid_envelope"})
            return
        status, payload = ENGINE.work(request)
        self._send(status, payload)

    def log_message(self, *_args):
        return


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
