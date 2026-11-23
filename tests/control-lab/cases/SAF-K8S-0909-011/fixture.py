"""Fixed synthetic HTTP retrieval and consumer fixture; standard library only."""
import hashlib
import json
import re
from pathlib import Path
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import Request, urlopen

CONSUMER = "http://retrieval-consumer:8081"
THRESHOLD = 0.75
PINS = Path("/trusted/chunks.json")
INDEX = Path("/indexed/chunks.json")
received = []


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def words(text):
    return set(re.findall(r"[a-z]+", text.lower()))


def relevance(text, query):
    terms = words(query)
    return len(terms & words(text)) / len(terms)


def decision(chunk, pins, query):
    chunk_id = chunk.get("id")
    if set(chunk) != {"id", "source", "version", "text"} or not all(isinstance(value, str) for value in chunk.values()):
        return "invalid_metadata", None
    expected = pins.get(chunk_id)
    if expected is None or chunk["source"] != expected["source"] or chunk["version"] != expected["version"]:
        return "source_or_version_unapproved", None
    if digest(chunk["text"]) != expected["sha256"]:
        return "digest_mismatch", None
    score = relevance(chunk["text"], query)
    return ("accepted" if score >= THRESHOLD else "below_threshold"), score


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass
    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        received.append(payload)
        body = {"received": True, "chunk_id": payload["chunk_id"], "text_sha256": digest(payload["text"])}
        raw = json.dumps(body, sort_keys=True).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        raw = json.dumps({"received_count": len(received)}, sort_keys=True).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

def serve():
    HTTPServer(("0.0.0.0", 8081), Handler).serve_forever()

def consumer_count():
    with urlopen(CONSUMER+"/count", timeout=5) as response:
        return json.load(response)["received_count"]


def admit(scenario, enforce):
    pins = json.loads(PINS.read_text())
    records = json.loads(INDEX.read_text())[scenario]
    query = records["query"]
    approved = []
    decisions = []
    for chunk in records["candidates"]:
        reason, score = decision(chunk, pins, query) if enforce else ("baseline", 0)
        decisions.append({"chunk_id": chunk.get("id"), "decision": reason, "score": score})
        if reason in ("accepted", "baseline"):
            approved.append((score, chunk))
    before = consumer_count()
    receipts = []
    for _, chunk in sorted(approved, key=lambda row: (-row[0], row[1]["id"]))[:1]:
        payload = json.dumps({"chunk_id": chunk["id"], "text": chunk["text"]}).encode()
        request = Request(CONSUMER+"/receive", data=payload, headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=5) as response:
            receipts.append(json.load(response))
    return {"decisions": decisions, "consumer_delta": consumer_count()-before, "receipts": receipts}


if __name__ == "__main__":
    if sys.argv[1] == "consumer":
        serve()
    else:
        scenario = sys.argv[1]
        print(json.dumps(admit(scenario, scenario != "baseline"), sort_keys=True))
