"""Deterministic synthetic RAG index, receiver, alert sink and scoped response."""
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys
from urllib.request import Request, urlopen

ROOT = Path("/data")
GENERATIONS = ROOT / "generations"
HELD = ROOT / "held"
STATE = ROOT / "state.json"
RECEIPTS = ROOT / "receipts.json"
ALERTS = Path("/alerts") / "events.json"
APPROVED_FILE = Path("/trusted") / "approved-generations.json"
REGISTRY = {
    "gen-cedar-v1": {"source_id": "synthetic://cedar", "version": "v1",
                      "chunk_id": "chunk-cedar", "text": "Cedar sample color is amber."},
    "gen-maple-v1": {"source_id": "synthetic://maple", "version": "v1",
                      "chunk_id": "chunk-maple", "text": "Maple sample color is green."},
}


def sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def read_json(path, fallback):
    return json.loads(path.read_text()) if path.exists() else fallback


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_suffix(".tmp")
    staged.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    staged.replace(path)


def approved_registry():
    return json.loads(APPROVED_FILE.read_text())


def initialize():
    GENERATIONS.mkdir(parents=True, exist_ok=True)
    HELD.mkdir(parents=True, exist_ok=True)
    for generation, item in REGISTRY.items():
        write_json(GENERATIONS / f"{generation}.json", {
            "generation": generation, "source_id": item["source_id"], "version": item["version"],
            "chunk_id": item["chunk_id"], "text": item["text"], "sha256": sha(item["text"]),
        })
    # One unapproved fixture generation reuses approved cedar metadata but carries different
    # harmless synthetic bytes. This is a fixed integrity discrepancy, not an attack recipe.
    suspect = REGISTRY["gen-cedar-v1"]
    write_json(GENERATIONS / "gen-unapproved.json", {
        "generation": "gen-unapproved", "source_id": suspect["source_id"], "version": suspect["version"],
        "chunk_id": suspect["chunk_id"], "text": "Cedar sample color is blue.", "sha256": sha(suspect["text"]),
    })
    write_json(STATE, {"active_generation": "gen-unapproved", "held_generations": [],
                       "monitoring": False, "scan_count": 0})
    write_json(RECEIPTS, [])


def get_url(path, base="CONSUMER_URL"):
    with urlopen(os.environ[base] + path, timeout=4) as response:
        return json.loads(response.read())


def post_json(url, payload):
    request = Request(url, data=json.dumps(payload, sort_keys=True).encode(),
                      headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=4) as response:
        return json.loads(response.read())


def send_consumer(generation):
    chunk = json.loads((GENERATIONS / f"{generation}.json").read_text())
    response = post_json(os.environ["CONSUMER_URL"] + "/receive", {
        "generation": generation, "chunk_id": chunk["chunk_id"], "text": chunk["text"]})
    return response


def baseline():
    before = get_url("/status")["count"]
    state = read_json(STATE, {})
    # The baseline exercises an unmonitored retrieval path and deliberately takes no response.
    result = send_consumer(state["active_generation"])
    after = get_url("/status")["count"]
    audit_count = get_url("/incident-status", "ALERT_URL")["count"]
    return {"forwarded": after == before + 1, "detection_count": state["scan_count"],
            "incident_count": audit_count,
            "active_generation": state["active_generation"], "consumer_delta": after - before,
            "consumer_receipt": result}


def scan():
    state = read_json(STATE, {})
    registry = approved_registry()
    state["monitoring"] = True
    state["scan_count"] += 1
    events = []
    for path in sorted(GENERATIONS.glob("*.json")):
        record = json.loads(path.read_text())
        approved = registry.get(record["generation"])
        observed = sha(record["text"])
        if approved is None:
            reason = "generation_not_approved"
            expected = None
        elif (record["source_id"] != approved["source_id"] or record["version"] != approved["version"]
              or record["chunk_id"] != approved["chunk_id"] or record["sha256"] != approved["sha256"]
              or observed != record["sha256"]):
            reason = "metadata_content_digest_mismatch"
            expected = approved["sha256"]
        else:
            continue
        event = {"event": "index-integrity-alert", "generation": record["generation"],
                 "reason": reason, "expected_sha256": expected, "observed_sha256": observed}
        events.append(event)

    response = None
    held = []
    if events:
        # Scope containment to the unapproved generation: preserve a record in held/ and
        # restore the active pointer to the registry-approved cedar generation.
        for event in events:
            generation = event["generation"]
            source = GENERATIONS / f"{generation}.json"
            HELD.mkdir(parents=True, exist_ok=True)
            source.replace(HELD / source.name)
            held.append(generation)
        state["held_generations"] = sorted(set(state["held_generations"] + held))
        if state["active_generation"] in held:
            state["active_generation"] = "gen-cedar-v1"
        state["last_incident_action"] = "held-scoped-generation-and-restored-approved-pointer"
    write_json(STATE, state)
    for event in events:
        response = post_json(os.environ["ALERT_URL"] + "/incident", event)
    return {"monitoring": state["monitoring"], "scan_count": state["scan_count"],
            "detections": events, "incident_action": state.get("last_incident_action"),
            "held_generations": state["held_generations"], "active_generation": state["active_generation"],
            "alert_receipt": response}


def release(generation):
    state = read_json(STATE, {})
    if not state.get("monitoring") or generation in state["held_generations"]:
        return {"accepted": False}
    registry = approved_registry()
    record = json.loads((GENERATIONS / f"{generation}.json").read_text())
    expected = registry.get(generation)
    if expected is None or any(record.get(key) != value for key,value in expected.items()):
        return {"accepted": False}
    if sha(record["text"]) != expected["sha256"]:
        return {"accepted": False}
    return send_consumer(generation)


def release_held():
    before = get_url("/status")["count"]
    result = release("gen-unapproved")
    return {"held_generation_denied": result == {"accepted": False},
            "consumer_delta": get_url("/status")["count"] - before}


def positive():
    before = get_url("/status")["count"]
    state = read_json(STATE, {})
    clean_scan = scan()
    # Release a distinct registry-approved ordinary generation after integrity monitoring.
    state = read_json(STATE, {})
    state["active_generation"] = "gen-maple-v1"
    write_json(STATE, state)
    result = release(state["active_generation"])
    after = get_url("/status")["count"]
    return {"monitoring_remains_enabled": clean_scan["monitoring"],
            "clean_scan_detected_nothing": clean_scan["detections"] == [],
            "clean_scan_emitted_no_incident": clean_scan["alert_receipt"] is None,
            "alert_count": get_url("/incident-status", "ALERT_URL")["count"],
            "approved_ordinary_generation_released": result["accepted"],
            "generation": "gen-maple-v1", "consumer_delta": after - before,
            "consumer_receipt": result, "held_generations": clean_scan["held_generations"]}


def alert_status():
    return get_url("/incident-status", "ALERT_URL")


def audit():
    state = read_json(STATE, {})
    return {"active_generation": state["active_generation"],
            "held_generations": state["held_generations"],
            "unapproved_generation_present_in_active_index":
                (GENERATIONS / "gen-unapproved.json").exists(),
            "held_generation_present": (HELD / "gen-unapproved.json").exists(),
            "monitoring": state["monitoring"], "scan_count": state["scan_count"]}


class Receiver(BaseHTTPRequestHandler):
    collection = None

    def log_message(self, *_args):
        pass

    def reply(self, status, value):
        raw = json.dumps(value, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self.reply(200, {"count": len(self.collection), "receipts": self.collection})

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        if "text" in payload:
            item = {"generation": payload["generation"], "chunk_id": payload["chunk_id"],
                    "text_sha256": sha(payload["text"]), "accepted": True}
        else:
            item = payload
        self.collection.append(item)
        if "text_sha256" not in item:
            write_json(ALERTS, self.collection)
        self.reply(200, {"received": True, **({"accepted": True, "generation": item["generation"]} if "text_sha256" in item else {})})


def serve(kind):
    if kind == "controller":
        initialize()
        class Controller(Receiver):
            collection = []
        # Control API is intentionally unused for corpus transport; the pod is an exec target.
        HTTPServer(("0.0.0.0", 8080), Controller).serve_forever()
    elif kind == "consumer":
        class Consumer(Receiver):
            collection = []
        HTTPServer(("0.0.0.0", 8081), Consumer).serve_forever()
    elif kind == "alerts":
        class Alerts(Receiver):
            collection = []
        HTTPServer(("0.0.0.0", 8082), Alerts).serve_forever()


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "serve":
        serve(sys.argv[2])
    elif mode == "baseline":
        print(json.dumps(baseline(), sort_keys=True))
    elif mode == "scan":
        print(json.dumps(scan(), sort_keys=True))
    elif mode == "release-held":
        print(json.dumps(release_held(), sort_keys=True))
    elif mode == "positive":
        print(json.dumps(positive(), sort_keys=True))
    elif mode == "audit":
        print(json.dumps(audit(), sort_keys=True))
    elif mode == "alert-status":
        print(json.dumps(alert_status(), sort_keys=True))
