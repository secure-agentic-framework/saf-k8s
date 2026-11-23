"""Serve public fixtures with a dedicated Kubernetes workload authentication check."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import ssl
from urllib.error import URLError
from urllib.request import Request, urlopen

AUDIENCE = 'saf-fixture-marker'
EXPECTED = 'system:serviceaccount:saf-test:fixture-marker-client'


def verified_identity(token):
    request = {'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenReview',
               'spec': {'token': token, 'audiences': [AUDIENCE]}}
    credential = Path('/identity/token').read_text().strip()
    url = 'https://kubernetes.default.svc/apis/authentication.k8s.io/v1/tokenreviews'
    api = Request(url, data=json.dumps(request).encode(), method='POST', headers={
        'Content-Type': 'application/json', 'Authorization': 'Bearer ' + credential})
    trust = ssl.create_default_context(cafile='/identity/ca.crt')
    with urlopen(api, context=trust, timeout=4) as reply:
        status = json.load(reply).get('status', {})
    return status.get('authenticated') is True and status.get('user', {}).get('username') == EXPECTED and AUDIENCE in status.get('audiences', [])


class Handler(BaseHTTPRequestHandler):
    def send(self, code, body):
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        if self.path == '/health':
            self.send(200, 'ready')
            return
        if self.path != '/marker':
            self.send(404, 'fixture')
            return
        if os.environ['MODE'] == 'comparison':
            self.send(200, 'public-comparison-marker')
            return
        authorization = self.headers.get('Authorization', '')
        try:
            valid = authorization.startswith('Bearer ') and verified_identity(authorization[7:])
        except URLError:
            self.send(503, 'fixture authentication unavailable')
            return
        if valid:
            self.send(200, 'public-identity-marker')
        else:
            self.send(401, 'fixture identity required')


HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
