"""Minimal local external-metrics API fixture for a disposable Kind cluster."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
from datetime import datetime, timezone


DEMAND = Path("/tmp/demand.json")
METRIC = "saf_fixture_demand"
LABELS = {"fixture": "SAF-K8S-0903-007"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _reply(self, code, body):
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/-/ready":
            self._reply(200, {"ready": True})
            return
        if self.path == "/__fixture/state":
            if self.client_address[0] not in ("127.0.0.1", "::1"):
                self._reply(403, {"error": "loopback only"})
                return
            self._reply(200, {"metric": METRIC, "value": int(DEMAND.read_text()), "labels": LABELS})
            return
        prefix = "/apis/external.metrics.k8s.io/v1beta1"
        if self.path == prefix:
            self._reply(200, {
                "apiVersion": "v1", "kind": "APIResourceList",
                "groupVersion": "external.metrics.k8s.io/v1beta1",
                "resources": [{"name": METRIC, "singularName": "", "namespaced": True,
                               "kind": "ExternalMetricValueList", "verbs": ["list"]}],
            })
            return
        if self.path.split("?", 1)[0] == f"{prefix}/namespaces/saf-0903-007/{METRIC}":
            self._reply(200, {
                "apiVersion": "external.metrics.k8s.io/v1beta1", "kind": "ExternalMetricValueList",
                "metadata": {},
                "items": [{"metricName": METRIC, "metricLabels": LABELS,
                           "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                           "value": str(int(DEMAND.read_text()))}],
            })
            return
        self._reply(404, {"error": "not found"})


if __name__ == "__main__":
    DEMAND.write_text(os.environ.get("INITIAL_DEMAND", "1"))
    server = ThreadingHTTPServer(("0.0.0.0", 6443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
