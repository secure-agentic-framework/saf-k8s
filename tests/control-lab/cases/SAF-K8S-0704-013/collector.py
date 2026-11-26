"""Small case-owned source reader/forwarder for synthetic onboarding evidence."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPConnection
import json
from pathlib import Path
import threading
import time

CONFIG = Path("/config/config.json")
PROVIDER = Path("/provider/provider.jsonl")
AUDIT = Path("/audit.jsonl")
MARKER = "audit-receipt-marker"
STATE = {"enrolled": [], "pending": 0, "failures": 0, "delivered": 0}
LOCK = threading.Lock()
ACKED = set()
PENDING = set()
FAILURES = 0


def records(config):
    rows = {}
    enrolled = set(config.get("enrolled_sources", []))
    if "provider-fixture" in enrolled:
        for line in PROVIDER.read_text().splitlines():
            if line.strip():
                row = json.loads(line)
                rows[(row["source_id"], row["record_id"])] = row
    if "kubernetes-apiserver" in enrolled and AUDIT.is_file():
        for line in AUDIT.read_text().splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            ref = event.get("objectRef", {})
            if (event.get("stage") != "ResponseComplete" or event.get("level") != "Metadata"
                    or "requestObject" in event or "responseObject" in event
                    or event.get("verb") != "patch"
                    or ref.get("resource") != "configmaps" or ref.get("name") != MARKER
                    or ref.get("namespace") != "saf-test"
                    or event.get("responseStatus", {}).get("code") != 200):
                continue
            event_id = event.get("auditID")
            if not event_id:
                continue
            row = {
                "source_id": "kubernetes-apiserver:" + config["cluster_id"],
                "source_type": "kubernetes-apiserver", "record_id": event_id,
                "category": "apiserver-metadata", "event_time": event.get("stageTimestamp"),
                "subject": event.get("user", {}).get("username", "unknown"),
                "verb": event["verb"], "status": event["responseStatus"]["code"],
                "synthetic": False,
            }
            rows[(row["source_id"], row["record_id"])] = row
    return rows


def status_handler():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/status":
                self.send_error(404)
                return
            with LOCK:
                payload = json.dumps(STATE, sort_keys=True).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format, *_args):
            return
    return Handler


def serve_status():
    ThreadingHTTPServer(("0.0.0.0", 8081), status_handler()).serve_forever()


def forward_loop():
    global FAILURES
    while True:
        try:
            config = json.loads(CONFIG.read_text())
            batch = records(config)
        except (OSError, ValueError, KeyError, TypeError):
            time.sleep(0.5)
            continue
        for key, row in batch.items():
            if key in ACKED:
                continue
            PENDING.add(key)
            try:
                body = json.dumps([row]).encode()
                connection = HTTPConnection("audit-sink", 8080, timeout=2)
                try:
                    connection.request("POST", "/ingest", body=body,
                                       headers={"Content-Type": "application/json"})
                    response = connection.getresponse()
                    response_body = json.loads(response.read())
                    if response.status != 201 or response_body.get("received") != 1:
                        raise ValueError("receiver did not acknowledge one record")
                finally:
                    connection.close()
                ACKED.add(key)
                PENDING.discard(key)
            except Exception:
                FAILURES += 1
        with LOCK:
            STATE.update({"enrolled": sorted(config.get("enrolled_sources", [])),
                          "pending": len(PENDING), "failures": FAILURES,
                          "delivered": len(ACKED)})
        time.sleep(0.5)


if __name__ == "__main__":
    threading.Thread(target=serve_status, daemon=True).start()
    forward_loop()
