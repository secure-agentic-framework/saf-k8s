"""Deterministic, benign in-memory inference queue used only by this local case."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import sys
from threading import RLock
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener


CONFIG = json.loads(Path("/case/queue.json").read_text(encoding="utf-8"))
JOB_BY_ID = {item["id"]: item for item in CONFIG["jobs"]}
ENFORCED = sys.argv[1:3] != ["serve", "baseline"]
LOCK = RLock()
STATE = {"clock": 0, "held": False, "pending": [], "executed": [], "receipts": {}}


def _receipt(job_id):
    receipt = STATE["receipts"].get(job_id)
    if receipt is None:
        raise ValueError(f"missing receipt for {job_id}")
    return receipt


def _expire_due():
    if not ENFORCED:
        return
    survivors = []
    for item in STATE["pending"]:
        if STATE["clock"] >= item["expires_at"]:
            receipt = _receipt(item["job_id"])
            receipt.update(status="expired", expired_at=STATE["clock"], execution_count=0)
        else:
            survivors.append(item)
    STATE["pending"] = survivors


def _pending_order(item):
    priority = CONFIG["class_priority"][item["service_class"]] if ENFORCED else 0
    return -priority, item["sequence"]


def _dispatch():
    _expire_due()
    while STATE["pending"] and not STATE["held"]:
        STATE["pending"].sort(
            key=_pending_order
        )
        item = STATE["pending"].pop(0)
        receipt = _receipt(item["job_id"])
        receipt.update(status="executed", executed_at=STATE["clock"], execution_count=1)
        STATE["executed"].append(item["job_id"])
        _expire_due()


def _public_state():
    _expire_due()
    ordered = sorted(
        STATE["pending"],
        key=_pending_order,
    )
    return {
        "event": "queue_state", "clock": STATE["clock"],
        "dispatch_held": STATE["held"],
        "pending": [item["job_id"] for item in ordered],
        "executed": list(STATE["executed"]),
        "receipts": [dict(STATE["receipts"][key]) for key in sorted(STATE["receipts"])],
    }


def _handle(body):
    op = body.get("op")
    with LOCK:
        if op == "state":
            return 200, _public_state()
        if op == "hold_dispatch":
            held = body.get("held")
            if not isinstance(held, bool):
                return 400, {"status": 400, "reason": "held_must_be_boolean"}
            STATE["held"] = held
            _dispatch()
            return 200, {"dispatch_held": STATE["held"]}
        if op == "advance_clock":
            ticks = body.get("ticks")
            if not isinstance(ticks, int) or ticks < 1 or ticks > 10:
                return 400, {"status": 400, "reason": "invalid_fixture_clock_step"}
            STATE["clock"] += ticks
            _expire_due()
            return 200, {"clock": STATE["clock"]}
        if op != "submit":
            return 404, {"status": 404, "reason": "unknown_operation"}

        job_id = body.get("job_id")
        job = JOB_BY_ID.get(job_id)
        if job is None:
            return 400, {"status": 400, "reason": "job_not_in_fixed_fixture"}
        if job_id in STATE["receipts"]:
            return 409, {"status": 409, "reason": "duplicate_job_id"}
        requested_class = body.get("service_class")
        principal = body.get("principal")
        receipt = {"job_id": job_id, "service_class": requested_class,
                   "principal": principal, "execution_count": 0}
        STATE["receipts"][job_id] = receipt

        expected = (requested_class == job["class"] and principal == job["principal"]
                    and body.get("ttl") == job["ttl"])
        grants = CONFIG["principal_classes"].get(principal, [])
        if not expected or requested_class not in grants:
            receipt.update(status="rejected", reason="service_class_not_authorized")
            return 403, {"status": 403, "reason": "service_class_not_authorized", "job_id": job_id}
        if ENFORCED and len(STATE["pending"]) >= CONFIG["max_pending"]:
            receipt.update(status="rejected", reason="queue_depth_limit")
            return 429, {"status": 429, "reason": "queue_depth_limit", "job_id": job_id}

        receipt.update(status="queued", accepted_at=STATE["clock"])
        STATE["pending"].append({
            "job_id": job_id, "service_class": requested_class,
            "expires_at": STATE["clock"] + job["ttl"],
            "sequence": len(STATE["receipts"]),
        })
        _dispatch()
        if receipt["status"] == "executed":
            return 200, {"status": 200, "job_id": job_id, "receipt": dict(receipt)}
        return 202, {"status": 202, "job_id": job_id, "receipt": dict(receipt)}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/ready":
            self._write(200, {"ready": True})
        elif self.path == "/state":
            with LOCK:
                self._write(200, _public_state())
        else:
            self._write(404, {"status": 404, "reason": "not_found"})

    def do_POST(self):
        if self.path != "/queue":
            self._write(404, {"status": 404, "reason": "not_found"})
            return
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            status, result = _handle(body)
        except (ValueError, TypeError, json.JSONDecodeError):
            status, result = 400, {"status": 400, "reason": "invalid_json_request"}
        self._write(status, result)

    def _write(self, status, result):
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        return


if len(sys.argv) > 1 and sys.argv[1] == "request":
    payload = json.loads(sys.argv[2])
    method = "GET" if payload.get("op") == "state" else "POST"
    endpoint = "http://127.0.0.1:8080/state" if method == "GET" else "http://127.0.0.1:8080/queue"
    data = None if method == "GET" else json.dumps(payload, sort_keys=True).encode()
    request = Request(endpoint, data=data, method=method,
                      headers={"Content-Type": "application/json"})
    try:
        with build_opener(ProxyHandler({})).open(request, timeout=3) as response:
            result = json.loads(response.read())
    except HTTPError as error:
        result = json.loads(error.read())
        if result.get("status") != error.code:
            raise ValueError("The HTTP status differs from the fixture receipt")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
elif len(sys.argv) > 1 and sys.argv[1] == "serve":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
else:
    raise SystemExit("usage: queue.py serve | request JSON")
