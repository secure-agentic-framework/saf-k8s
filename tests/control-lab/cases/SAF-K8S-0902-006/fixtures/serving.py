"""Small, synthetic cache-key and admission-accounting fixture; not an LLM server."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
import threading
import time


PORT = 8080
MAX_CACHE_ENTRIES = 8
MAX_ACTIVE = 1
MAX_QUEUED = 1
FIXED_PUBLIC_CONTENT = "Public fixture: the sky appears blue on a clear day."
PREFIX_ID = "public-fixture-prefix-1"
MARKER = "SAF-SYNTHETIC-MOCK-RESULT-0902-006"
ALLOWED_TENANTS = {"tenant-a", "tenant-b"}
ALLOWED_FIXTURES = {PREFIX_ID, "tiny-1", "tiny-2"}


class FixtureState:
    def __init__(self):
        self.lock = threading.Condition()
        self.scoped = os.environ.get("CACHE_TENANT_SCOPE", "false").lower() == "true"
        # Opaque per-process fixture labels stand in for a gateway-supplied per-tenant
        # cache_salt. They are deliberately synthetic, never returned or logged.
        self.fixture_salts = {tenant: f"FIXTURE-ONLY-{tenant}-SALT" for tenant in ALLOWED_TENANTS}
        self.cache = {}
        self.cache_hits = 0
        self.cache_misses = 0
        self.last_tenant_by_key = {}
        self.cross_tenant_reuse_count = 0
        self.active = 0
        self.queued = 0
        self.peak_queue = 0
        self.released = False

    def key(self, tenant, content):
        prefix_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        scope = self.fixture_salts[tenant] if self.scoped else "UNSCOPED-FIXTURE"
        return hashlib.sha256((scope + ":" + prefix_hash).encode("utf-8")).hexdigest()

    def state(self):
        with self.lock:
            return {
                "tenant_scope": self.scoped,
                "cache_entries": len(self.cache), "cache_hits": self.cache_hits,
                "cache_misses": self.cache_misses,
                "cross_tenant_reuse_count": self.cross_tenant_reuse_count,
                "queue_active": self.active, "queue_depth": self.queued,
                "queue_peak_depth": self.peak_queue,
                "queue_max_active": MAX_ACTIVE, "queue_max_depth": MAX_QUEUED,
            }


STATE = FixtureState()


class Handler(BaseHTTPRequestHandler):
    server_version = "SAF-Synthetic-Fixture/1"
    sys_version = ""

    def log_message(self, _format, *_args):
        # Default HTTP logging can include request paths. Emit no request-derived text.
        return

    def send_json(self, status, value):
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_object(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 2 or length > 256:
                return None
            value = json.loads(self.rfile.read(length))
            if not isinstance(value, dict) or set(value) != {"event_id", "tenant", "fixture_id"}:
                return None
            if value["tenant"] not in ALLOWED_TENANTS or value["fixture_id"] not in ALLOWED_FIXTURES:
                return None
            if value["event_id"] not in {"red-a", "red-b", "green-a1", "green-b1",
                                         "positive-b2", "queue-a", "queue-b", "queue-c"}:
                return None
            return value
        except (ValueError, json.JSONDecodeError):
            return None

    def do_GET(self):
        if self.path == "/health":
            return self.send_json(200, {"ready": True})
        if self.path == "/state":
            return self.send_json(200, STATE.state())
        return self.send_json(404, {"error": "fixture-route-not-found"})

    def do_POST(self):
        if self.path == "/fixture/release":
            with STATE.lock:
                STATE.released = True
                STATE.lock.notify_all()
            return self.send_json(200, {"released": True})
        value = self.read_object()
        if value is None:
            return self.send_json(400, {"error": "fixture-request-invalid"})
        if self.path == "/infer":
            content = FIXED_PUBLIC_CONTENT if value["fixture_id"] == PREFIX_ID else value["fixture_id"]
            key = STATE.key(value["tenant"], content)
            with STATE.lock:
                hit = key in STATE.cache
                if hit:
                    STATE.cache_hits += 1
                    prior_tenant = STATE.last_tenant_by_key.get(key)
                    if prior_tenant is not None and prior_tenant != value["tenant"]:
                        STATE.cross_tenant_reuse_count += 1
                else:
                    STATE.cache_misses += 1
                    if len(STATE.cache) >= MAX_CACHE_ENTRIES:
                        return self.send_json(503, {"error": "fixture-cache-capacity"})
                    STATE.cache[key] = "synthetic-prefix-accounting-entry"
                STATE.last_tenant_by_key[key] = value["tenant"]
            return self.send_json(200, {"event_id": value["event_id"], "tenant": value["tenant"],
                                        "prefix_id": PREFIX_ID,
                                        "result": MARKER})
        if self.path == "/queue":
            with STATE.lock:
                deadline = time.monotonic() + 8
                if STATE.active < MAX_ACTIVE:
                    STATE.active += 1
                elif STATE.queued < MAX_QUEUED:
                    STATE.queued += 1
                    STATE.peak_queue = max(STATE.peak_queue, STATE.queued)
                    STATE.lock.wait_for(lambda: STATE.active < MAX_ACTIVE, timeout=max(0, deadline - time.monotonic()))
                    STATE.queued -= 1
                    if STATE.active >= MAX_ACTIVE:
                        return self.send_json(503, {"error": "fixture-queue-timeout"})
                    STATE.active += 1
                else:
                    return self.send_json(429, {"error": "fixture-queue-full"})
                released = value["event_id"] != "queue-a" or STATE.lock.wait_for(
                    lambda: STATE.released, timeout=max(0, deadline - time.monotonic()))
                STATE.active -= 1
                STATE.lock.notify_all()
            if not released:
                return self.send_json(503, {"error": "fixture-gate-timeout"})
            return self.send_json(200, {"event_id": value["event_id"], "result": MARKER})
        return self.send_json(404, {"error": "fixture-route-not-found"})


ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
