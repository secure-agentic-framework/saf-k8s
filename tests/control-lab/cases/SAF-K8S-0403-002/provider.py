"""Serve a synthetic HTTPS secret source with in-memory auth-decision counts only."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import ssl

SOURCE = Path("/source")
AUTH = Path("/auth")
DECISIONS = {"authorized_requests": 0, "refused_requests": 0, "refused_principal_requests": 0,
             "refused_token_requests": 0, "authorized_unavailable_requests": 0}


def _response(handler, status, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(raw)))
    handler.send_header("Connection", "close")
    handler.end_headers()
    handler.wfile.write(raw)
    handler.close_connection = True


class Provider(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/__fixture/decisions":
            # This separate, in-memory observation exposes outcome counts, never header values.
            return _response(self, 200, DECISIONS)
        if self.path != "/fixture-value":
            return _response(self, 404, {"error": "not-found"})

        expected_principal = (AUTH / "principal").read_text(encoding="utf-8").strip()
        expected_token = (AUTH / "token").read_text(encoding="utf-8").strip()
        principal = self.headers.get("X-SAF-Principal", "")
        token = self.headers.get("X-SAF-Token", "")
        if principal != expected_principal or token != expected_token:
            DECISIONS["refused_requests"] += 1
            if principal != expected_principal:
                DECISIONS["refused_principal_requests"] += 1
            if token != expected_token:
                DECISIONS["refused_token_requests"] += 1
            return _response(self, 403, {"error": "fixture-principal-refused"})

        DECISIONS["authorized_requests"] += 1
        if (SOURCE / "available").read_text(encoding="utf-8").strip() != "yes":
            DECISIONS["authorized_unavailable_requests"] += 1
            return _response(self, 503, {"error": "fixture-source-unavailable"})
        return _response(self, 200, {"value": (SOURCE / "value").read_text(encoding="utf-8").strip()})

    def log_message(self, *args):
        # Never emit headers, request values, response values, or request lines.
        return

    def log_error(self, *args):
        return


api = HTTPServer(("0.0.0.0", 9443), Provider)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
api.socket = tls.wrap_socket(api.socket, server_side=True)
api.serve_forever()
