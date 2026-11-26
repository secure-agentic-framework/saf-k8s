"""Serve fixed inputs using the attached, digest-verified synthetic model."""
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path


model_bytes = Path('/fixture/model.json').read_bytes()
model_digest = 'sha256:' + sha256(model_bytes).hexdigest()
if model_digest != os.environ['SAF_FIXTURE_MODEL_DIGEST']:
    raise RuntimeError('The mounted model bytes differ from the selected digest')
model = json.loads(model_bytes)
inputs = [-1, 0, 3]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/healthz':
            self.send_response(200)
            self.end_headers()
        elif self.path == '/predict':
            result = json.dumps({'model_digest': model_digest,
                                 'release': os.environ['SAF_FIXTURE_RELEASE'],
                                 'inputs': inputs,
                                 'predictions': [model['coefficient'] * x + model['intercept'] for x in inputs]}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(result)))
            self.end_headers()
            self.wfile.write(result)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *_):
        pass


HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
