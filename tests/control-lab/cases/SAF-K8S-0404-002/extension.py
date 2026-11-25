"""Minimal case-owned HTTPS admission and aggregation endpoints."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import json
import ssl
from urllib.parse import parse_qs, urlsplit

GROUP = "extension-fixture.saf-k8s.example"
VERSION = GROUP + "/v1"


class Handler(BaseHTTPRequestHandler):
    def answer(self, status, data):
        payload = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def record_protocol(self, route):
        print("fixture-protocol " + json.dumps({"route": route, "tls": self.connection.version()}), flush=True)

    def do_GET(self):
        path = urlsplit(self.path).path
        print("fixture GET " + path, flush=True)
        if path == "/apis/" + VERSION:
            self.answer(200, {"apiVersion": "v1", "kind": "APIResourceList", "groupVersion": VERSION,
                              "resources": [{"name": "fixturemarkers", "singularName": "fixturemarker",
                                             "namespaced": False, "kind": "FixtureMarker", "verbs": ["list"]}]})
        elif path == "/apis/" + VERSION + "/fixturemarkers":
            self.record_protocol("aggregation")
            probe = parse_qs(urlsplit(self.path).query).get("probe", ["fixture-existing-marker"])[0]
            if probe.startswith("fixture-availability-"):
                print("fixture-aggregating " + json.dumps({"route": "aggregate", "probe": probe,
                                                            "tls": self.connection.version()}), flush=True)
            self.answer(200, {"apiVersion": VERSION, "kind": "FixtureMarkerList", "metadata": {},
                              "items": [{"apiVersion": VERSION, "kind": "FixtureMarker",
                                         "metadata": {"name": "owned-aggregation-marker"}}]})
        else:
            self.answer(404, {"message": "unknown fixture path"})

    def do_POST(self):
        review = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        request = review["request"]
        path = urlsplit(self.path).path
        if path == "/mutate":
            name = request.get("name", "")
            if (request.get("dryRun") is not True or request.get("operation") != "CREATE"
                    or request.get("namespace") != "saf-test"
                    or request.get("resource", {}).get("resource") != "configmaps"
                    or not name.startswith("fixture-mutator-")):
                self.send_error(400)
                return
            self.record_protocol("mutation")
            print("fixture-mutating " + json.dumps({"route": "mutate", "probe": name,
                                                      "tls": self.connection.version()}), flush=True)
            patch = [{"op": "add", "path": "/metadata/annotations/saf-k8s.example~1mutated",
                      "value": "yes"}]
            response = {"uid": request["uid"], "allowed": True, "patchType": "JSONPatch",
                        "patch": base64.b64encode(json.dumps(patch, separators=(",", ":")).encode()).decode()}
            self.answer(200, {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
                              "response": response})
            return
        if path != "/admit":
            self.send_error(404)
            return
        if request["object"].get("metadata", {}).get("name") == "fixture-admission-probe":
            self.record_protocol("admission")
        probe_name = request.get("object", {}).get("metadata", {}).get("name", "")
        if probe_name.startswith("fixture-mutator-validator-"):
            print("fixture-validating " + json.dumps({"route": "validate", "probe": probe_name,
                                                        "tls": self.connection.version()}), flush=True)
        allowed = "deny" not in request["object"].get("data", {})
        response = {"uid": request["uid"], "allowed": allowed}
        if not allowed:
            response["status"] = {"message": "Owned extension deliberately denies this public fixture"}
        self.answer(200, {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "response": response})

    def log_message(self, *_):
        pass


listener = HTTPServer(("0.0.0.0", 8443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
listener.socket = context.wrap_socket(listener.socket, server_side=True)
listener.serve_forever()
