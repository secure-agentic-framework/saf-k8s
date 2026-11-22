"""Deterministic synthetic inference policy fixture; no model or accelerator is used."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os


POLICIES = {
    "weak": {"max_input_bytes": None, "request_work": None, "session_work": None,
             "batch_items": None, "request_ticks": None, "session_ticks": None,
             "batch_ticks": None, "max_inflight": None},
    "strong": {"max_input_bytes": 64, "request_work": 3, "session_work": 4,
               "batch_items": 2, "request_ticks": 2, "session_ticks": 4,
               "batch_ticks": 5, "max_inflight": 1},
}


class Engine:
    def __init__(self, mode):
        if mode not in POLICIES:
            raise ValueError("unknown POLICY_MODE")
        self.mode = mode
        self.policy = POLICIES[mode]
        self.counters = {key: 0 for key in (
            "accepted", "input_rejected", "request_budget_rejected",
            "session_budget_rejected", "batch_budget_rejected", "request_timeout",
            "session_timeout", "batch_timeout", "degraded", "work_units_executed")}
        self.sessions = {}

    def _compute(self, units):
        # Each accepted unit performs exactly 128 small integer operations.
        # Policy checks happen before work; the fixture input cannot raise this bound.
        units = min(max(int(units), 0), 8)
        checksum = 0
        for unit in range(units):
            value = unit + 1
            for _ in range(128):
                value = (value * 33 + 17) % 65521
            checksum ^= value
        self.counters["work_units_executed"] += units
        return checksum

    def infer(self, *, content, work_units=1, session="default", batch_items=1,
              request_elapsed=0, session_elapsed=0, batch_elapsed=0, overload=False):
        p = self.policy
        input_bytes = len(content.encode("utf-8"))
        work_units = int(work_units)
        batch_items = int(batch_items)
        if p["max_input_bytes"] is not None and input_bytes > p["max_input_bytes"]:
            self.counters["input_rejected"] += 1
            return {"status": 413, "reason": "input_limit"}
        if p["request_work"] is not None and work_units > p["request_work"]:
            self.counters["request_budget_rejected"] += 1
            return {"status": 429, "reason": "request_budget"}
        previous = self.sessions.get(session, 0)
        if p["session_work"] is not None and previous + work_units > p["session_work"]:
            self.counters["session_budget_rejected"] += 1
            return {"status": 429, "reason": "session_budget"}
        if p["batch_items"] is not None and batch_items > p["batch_items"]:
            self.counters["batch_budget_rejected"] += 1
            return {"status": 413, "reason": "batch_limit"}
        for name, elapsed, limit in (
            ("request_timeout", int(request_elapsed), p["request_ticks"]),
            ("session_timeout", int(session_elapsed), p["session_ticks"]),
            ("batch_timeout", int(batch_elapsed), p["batch_ticks"]),
        ):
            if limit is not None and elapsed > limit:
                self.counters[name] += 1
                return {"status": 504, "reason": name}
        if overload and p["max_inflight"] is not None and 2 > p["max_inflight"]:
            self.counters["degraded"] += 1
            checksum = self._compute(1)
            self.counters["accepted"] += 1
            return {"status": 200, "reason": "degraded", "quality": "reduced",
                    "work_units": 1, "checksum": checksum}
        self.sessions[session] = previous + work_units
        checksum = self._compute(work_units)
        self.counters["accepted"] += 1
        return {"status": 200, "reason": "accepted", "input_bytes": input_bytes,
                "work_units": work_units, "checksum": checksum}


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, payload):
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.respond(200, {"ready": True})
        elif self.path == "/__fixture/state":
            self.respond(200, {"fixture_id": "SAF-K8S-0903-003-synthetic-v1",
                               "mode": self.server.engine.mode,
                               "counters": self.server.engine.counters})
        else:
            self.respond(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/infer":
            self.respond(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 4096:
            self.respond(400, {"error": "invalid fixture envelope"})
            return
        request = json.loads(self.rfile.read(length))
        result = self.server.engine.infer(**request)
        self.respond(result["status"], result)

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    if os.environ.get("POLICY_MODE") not in POLICIES:
        raise SystemExit("POLICY_MODE must be weak or strong")
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    server.engine = Engine(os.environ["POLICY_MODE"])
    server.serve_forever()
