"""Export freshness from a live authorized read of one fixture Application."""
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
from urllib.error import URLError
from urllib.request import Request, urlopen

IDENTITY = Path("/identity")
FIXTURE = "saf-health-fixture"
API = f"https://kubernetes.default.svc/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/{FIXTURE}"
LABELS = f'namespace="argocd",name="{FIXTURE}"'
TLS = ssl.create_default_context(cafile=str(IDENTITY / "ca.crt"))


def metrics():
    request = Request(API, headers={
        "Authorization": "Bearer " + (IDENTITY / "token").read_text().strip(),
    })
    try:
        with urlopen(request, context=TLS, timeout=4) as response:
            application = json.load(response)
        metadata, status = application["metadata"], application["status"]
        if metadata["name"] != FIXTURE or metadata["namespace"] != "argocd":
            raise ValueError("Unexpected fixture metadata")
        stamp = datetime.fromisoformat(status["reconciledAt"].replace("Z", "+00:00")).timestamp()
        healthy = int(status["sync"]["status"] == "Synced" and status["health"]["status"] == "Healthy")
    except (OSError, URLError, ValueError, KeyError):
        return f"saf_fixture_api_read_success{{{LABELS}}} 0\n"
    return (f"saf_fixture_api_read_success{{{LABELS}}} 1\n"
            f"saf_fixture_application_healthy{{{LABELS}}} {healthy}\n"
            f"saf_fixture_reconciliation_timestamp_seconds{{{LABELS}}} {stamp:.0f}\n")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404)
            return
        body = metrics().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
