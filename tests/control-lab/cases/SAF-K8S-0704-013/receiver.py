"""Case-owned mTLS destination with durable, source-aware receipt deduplication."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl

STORE = Path("/data/receipts.jsonl")
SOURCES = {"kubernetes-apiserver", "provider-fixture"}
FIELDS = {"source_id", "source_type", "record_id", "category", "event_time",
          "subject", "verb", "status", "synthetic"}


def existing():
    if not STORE.exists():
        return []
    return [json.loads(line) for line in STORE.read_text().splitlines() if line.strip()]


class Handler(BaseHTTPRequestHandler):
    def peer_uri(self):
        certificate = self.connection.getpeercert()
        return next((value for kind, value in certificate.get("subjectAltName", []) if kind == "URI"), None)

    def do_GET(self):
        if self.path == "/healthz":
            payload = b"ok\n"
        elif self.path == "/records":
            if self.peer_uri() != "spiffe://cluster.local/ns/saf-test/sa/audit-independent-reader":
                self.send_error(403)
                return
            payload = json.dumps(existing(), sort_keys=True).encode()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if self.path != "/ingest":
            self.send_error(404)
            return
        if self.peer_uri() != "spiffe://cluster.local/ns/saf-test/sa/audit-source-collector":
            self.send_error(403)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise ValueError("invalid bounded body")
            batch = json.loads(self.rfile.read(length))
            if not isinstance(batch, list) or not 1 <= len(batch) <= 8:
                raise ValueError("expected a small list")
            for row in batch:
                if (not isinstance(row, dict) or set(row) != FIELDS
                        or row["source_type"] not in SOURCES
                        or not isinstance(row["source_id"], str)
                        or not isinstance(row["record_id"], str)
                        or not row["record_id"]):
                    raise ValueError("invalid receipt schema")
                if row["source_type"] == "provider-fixture" and row["synthetic"] is not True:
                    raise ValueError("provider fixture must remain synthetic")
                if row["source_type"] == "provider-fixture" and not row["source_id"].startswith("provider-fixture:"):
                    raise ValueError("provider fixture source identity is invalid")
                if row["source_type"] == "kubernetes-apiserver" and row["synthetic"] is not False:
                    raise ValueError("observed API record must retain observed classification")
                if row["source_type"] == "kubernetes-apiserver" and not row["source_id"].startswith("kubernetes-apiserver:"):
                    raise ValueError("API source identity is invalid")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            self.send_error(400)
            return

        records = existing()
        seen = {(r["source_id"], r["record_id"]) for r in records}
        added = 0
        with STORE.open("a", encoding="utf-8") as output:
            for row in batch:
                key = (row["source_id"], row["record_id"])
                if key in seen:
                    continue
                output.write(json.dumps(row, sort_keys=True) + "\n")
                seen.add(key)
                added += 1
            output.flush()
            os.fsync(output.fileno())
        payload = json.dumps({"accepted": added, "received": len(batch)}).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format, *_args):
        return


if __name__ == "__main__":
    class QuietTLSHTTPServer(ThreadingHTTPServer):
        def handle_error(self, _request, _client_address):
            # Expected certificate-less comparison failures carry no request data.
            return

    server = QuietTLSHTTPServer(("0.0.0.0", 8443), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    tls.load_verify_locations(cafile="/ca/ca.crt")
    tls.verify_mode = ssl.CERT_REQUIRED
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
