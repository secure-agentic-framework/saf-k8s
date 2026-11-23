"""Fixed synthetic repository, admission client, and PVC consumer HTTP services."""
import base64
import hashlib
import json
import os
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener
from urllib.parse import urlsplit

PATH = "/fixed/field-notes.txt"
APPROVED_ID = "repo:synthetic:cedar-notes:42"
UNAPPROVED_ID = "repo:synthetic:meadow-notes:17"
APPROVED_REPO = "saf-source-allowlist-approved"
UNAPPROVED_REPO = "saf-source-allowlist-unregistered"
CONSUMERS = ("saf-source-allowlist-consumer-a", "saf-source-allowlist-consumer-b")
APPROVED_BYTES = b"The cedar notebook records a calm morning beside the garden gate.\n"
UNAPPROVED_BYTES = b"The meadow notebook records a quiet afternoon beside the stone bridge.\n"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(method, url, body=None, headers=None):
    parsed = urlsplit(url)
    hosts = {APPROVED_REPO, UNAPPROVED_REPO, *CONSUMERS}
    fixed_paths = {PATH, "/stats", "/state", "/ingest"}
    if (parsed.scheme != "https" or parsed.netloc not in {host + ".saf-test.svc:8080" for host in hosts}
            or parsed.path not in fixed_paths or parsed.query or parsed.fragment
            or parsed.username is not None or parsed.password is not None):
        raise ValueError("fixture URL is outside the fixed in-namespace service set")
    req = Request(url, data=body, headers=headers or {}, method=method)
    try:
        context = ssl.create_default_context(cafile="/trust/ca.crt")
        with build_opener(ProxyHandler({}), NoRedirect, HTTPSHandler(context=context)).open(req, timeout=6) as response:
            raw = response.read(8192)
            return {"status": response.status, "body_b64": base64.b64encode(raw).decode("ascii")}
    except HTTPError as exc:
        return {"status": exc.code, "body_b64": ""}
    except (URLError, TimeoutError) as exc:
        return {"status": 599, "error": type(exc).__name__}


def unpack(response):
    if response.get("status") != 200:
        raise RuntimeError("fixed local service request failed")
    return base64.b64decode(response["body_b64"], validate=True)


def ingest(mode, source_id):
    """Candidate carries an exact repository ID, never a caller-provided URL or path."""
    registry = json.loads(Path("/registry/registry.json").read_text())
    record = registry["repositories"].get(source_id) if mode == "locked" else None
    if mode == "locked" and record is None:
        print(json.dumps({"decision": "rejected", "reason": "repository_id_not_registered",
                          "source_id": source_id, "fetches": 0, "downstream_writes": 0},
                         sort_keys=True))
        return
    if mode not in ("open", "locked"):
        raise ValueError("unknown fixed gate mode")
    if record is not None:
        endpoint, expected = record["endpoint"], record["sha256"]
        token = Path("/tokens/approved").read_text()
        if record.get("path") != PATH:
            raise RuntimeError("registry path does not match fixture path")
    else:
        # Disabled-gate baseline only: this offline table has one fixed unregistered test case.
        routes = {UNAPPROVED_ID: (f"https://{UNAPPROVED_REPO}.saf-test.svc:8080{PATH}",
                                  Path("/tokens/unregistered").read_text())}
        if source_id not in routes:
            raise ValueError("source ID is not one of the fixed benign candidates")
        endpoint, token = routes[source_id]
        expected = None
    if endpoint not in (f"https://{APPROVED_REPO}.saf-test.svc:8080{PATH}",
                        f"https://{UNAPPROVED_REPO}.saf-test.svc:8080{PATH}"):
        raise RuntimeError("registry endpoint is outside the fixed fixture mapping")
    fetched = unpack(request("GET", endpoint, headers={"Authorization": "Bearer " + token}))
    digest = hashlib.sha256(fetched).hexdigest()
    if expected is not None and digest != expected:
        print(json.dumps({"decision": "rejected", "reason": "registered_bytes_mismatch",
                          "source_id": source_id, "fetches": 1, "downstream_writes": 0},
                         sort_keys=True))
        return
    headers = {"Content-Type": "application/octet-stream", "X-Source-Id": source_id}
    for consumer in CONSUMERS:
        result = request("POST", f"https://{consumer}.saf-test.svc:8080/ingest", fetched, headers)
        if result.get("status") != 201:
            raise RuntimeError("fixed consumer write failed")
    print(json.dumps({"decision": "accepted", "source_id": source_id,
                      "registry_match": record is not None, "fetched_sha256": digest,
                      "fetches": 1, "downstream_writes": len(CONSUMERS)}, sort_keys=True))


class Handler(BaseHTTPRequestHandler):
    server_version = "FixedRepositoryFixture/1"

    def log_message(self, fmt, *args):
        return

    def send_json(self, status, value):
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        role = self.server.role
        if role == "repository" and self.path == "/stats":
            self.send_json(200, {"fetches": self.server.fetches})
            return
        if role == "repository" and self.path == PATH:
            self.server.fetches += 1
            if self.headers.get("Authorization") != "Bearer " + Path("/tokens/repository").read_text():
                self.send_json(401, {"error": "fixed_identity_required"})
                return
            raw = base64.b64decode(os.environ["REPOSITORY_CONTENT_B64"], validate=True)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if role == "consumer" and self.path == "/state":
            file = Path(os.environ["DATA_FILE"])
            rows = []
            if file.exists():
                for line in file.read_text().splitlines():
                    rows.append(json.loads(line))
            self.send_json(200, {"records": rows})
            return
        self.send_json(404, {"error": "fixed_path_not_found"})

    def do_POST(self):
        if self.server.role != "consumer" or self.path != "/ingest":
            self.send_json(404, {"error": "fixed_path_not_found"})
            return
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 4096:
            self.send_json(413, {"error": "fixed_fixture_size_limit"})
            return
        raw = self.rfile.read(size)
        record = {"source_id": self.headers.get("X-Source-Id", ""),
                  "sha256": hashlib.sha256(raw).hexdigest(),
                  "bytes_b64": base64.b64encode(raw).decode("ascii")}
        with open(os.environ["DATA_FILE"], "a", encoding="utf-8") as out:
            out.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            out.flush()
            os.fsync(out.fileno())
        self.send_json(201, {"persisted": True, "sha256": record["sha256"]})


def serve(role):
    http = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    http.role = role
    http.fetches = 0
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    http.socket = context.wrap_socket(http.socket, server_side=True)
    http.serve_forever()


def main(argv):
    action = argv[1]
    if action == "serve":
        serve(argv[2])
    elif action == "ingest":
        ingest(argv[2], argv[3])
    elif action == "request":
        raw = None if argv[4] == "-" else base64.b64decode(argv[4], validate=True)
        print(json.dumps(request(argv[2], argv[3], raw, json.loads(argv[5])), sort_keys=True))
    elif action == "idle":
        while True:
            time.sleep(3600)
    else:
        raise ValueError("unsupported fixture action")


if __name__ == "__main__":
    main(sys.argv)
