"""Serve an inert, versioned dataset manifest inside the owned fixture namespace."""
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import sys
from urllib.request import ProxyHandler, build_opener

SOURCE = Path("/fixture/authoritative_dataset_manifest.json")
ACTIVE = Path("/data/current")
URL = "http://dataset-catalog.saf-1007-013-owned.svc.cluster.local:8080/dataset"


class Catalog(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/dataset":
            self.send_error(404)
            return
        dataset = json.loads(SOURCE.read_text())
        index = int(ACTIVE.read_text()) if ACTIVE.exists() else 0
        version = dataset["versions"][index]
        body = json.dumps({"source_identity": dataset["source_identity"],
                           "dataset_id": dataset["dataset_id"], "version": version},
                          sort_keys=True, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", '"' + sha256(body).hexdigest() + '"')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if sys.argv[1:] == ["serve"]:
    HTTPServer(("0.0.0.0", 8080), Catalog).serve_forever()
elif sys.argv[1:] == ["advance"]:
    path = ACTIVE.with_suffix(".next")
    path.write_text("1")
    path.replace(ACTIVE)
elif sys.argv[1:] == ["read"]:
    # A fixed Service URL with direct ingress into the owned namespace.
    with build_opener(ProxyHandler({})).open(URL, timeout=10) as response:
        body = response.read(65536)
        digest = sha256(body).hexdigest()
        if response.headers.get("ETag") != '"' + digest + '"':
            raise ValueError("dataset catalog ETag and response body differ")
    print(json.dumps({"result": json.loads(body), "etag": digest}, sort_keys=True))
else:
    raise SystemExit("expected serve, advance, or read")
