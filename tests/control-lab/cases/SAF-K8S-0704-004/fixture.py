"""Serve an inert marker using a short-lived, fixture-local session."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import secrets
import time

sessions = {}


class Fixture(BaseHTTPRequestHandler):
    def send(self, code, body):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def do_POST(self):
        if self.path != '/fixture-session':
            self.send(404, {})
            return
        token = secrets.token_hex(16)
        sessions[token] = time.monotonic() + 2
        self.send(201, {'fixture_session': token})

    def do_GET(self):
        if self.path == '/health':
            self.send(200, {'status': 'ready'})
            return
        if self.path != '/marker':
            self.send(404, {})
            return
        token = self.headers.get('X-Fixture-Session')
        if os.environ['REQUIRE_SESSION'] == 'yes' and sessions.get(token, 0) <= time.monotonic():
            self.send(401, {'fixture': 'session-required'})
            return
        self.send(200, {'fixture': 'public-node-marker'})


HTTPServer(('0.0.0.0', 8080), Fixture).serve_forever()
