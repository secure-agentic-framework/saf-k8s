"""Serve a harmless deterministic model parity check in the patch fixture."""
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path

RUNTIME = os.environ["SAF_RUNTIME_REVISION"]
MODEL = Path("/model/model.json").read_bytes()
MODEL_SHA = sha256(MODEL).hexdigest()
if MODEL_SHA != os.environ["SAF_EXPECTED_MODEL"]:
    raise SystemExit("model digest does not match the reviewed artifact")

WEIGHTS = json.loads(MODEL)["weights"]
PREDICTION = sum(coefficient * feature for coefficient, feature in zip(WEIGHTS, [4, 2], strict=True))
if RUNTIME == "incompatible":
    PREDICTION += 1


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        body = {"runtime": RUNTIME, "model_sha256": MODEL_SHA, "fixture_prediction": PREDICTION}
        payload = json.dumps(body).encode()
        self.send_response(200 if path == "/probe" else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        pass


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
