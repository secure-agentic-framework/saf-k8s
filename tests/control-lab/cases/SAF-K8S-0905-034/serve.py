"""Fixture model endpoints plus a simple weighted router."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import ssl
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

MODE = os.environ["MODE"]
PORT = 8080
UPSTREAM = {"stable": "http://model.saf-model-stable.svc:8080",
            "candidate": "http://model.saf-model-candidate.svc:8080"}
ROOT = Path("/var/run/secrets/kubernetes.io/serviceaccount")


def active_weight():
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ["KUBERNETES_SERVICE_PORT_HTTPS"]
    uri = f"https://{host}:{port}/api/v1/namespaces/saf-test/configmaps/route-policy"
    tls = ssl.create_default_context(cafile=str(ROOT / "ca.crt"))
    headers = {"Authorization": "Bearer " + (ROOT / "token").read_text().strip()}
    with urlopen(Request(uri, headers=headers), timeout=3, context=tls) as response:
        weight = int(json.load(response)["data"]["candidatePercent"])
    if not 0 <= weight <= 100:
        raise ValueError("out-of-range routing weight")
    return weight


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, message):
        body = message.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass

    def do_GET(self):
        route = urlsplit(self.path)
        if route.path == "/health":
            self.respond(200, "ready")
        elif route.path != "/model":
            self.respond(404, "unknown-route")
        elif MODE != "route":
            self.respond(200, MODE)
        else:
            slot = int(parse_qs(route.query)["id"][0]) % 100
            selected = "candidate" if slot < active_weight() else "stable"
            try:
                with urlopen(UPSTREAM[selected] + "/model", timeout=3) as response:
                    self.respond(response.status, response.read().decode())
            except OSError:
                self.respond(503, "fixture-backend-unavailable")


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
