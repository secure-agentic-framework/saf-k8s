"""UPDATE-only signature gate for the inert continuous-learning fixture."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
from urllib.parse import urlsplit
import webhook


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Do not log AdmissionReview bodies, annotations, or signatures.
        return

    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_error(404)

    def do_POST(self):
        if urlsplit(self.path).path != "/validate":
            self.send_error(404)
            return
        request = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        uid = request.get("request", {}).get("uid", "")
        obj = request.get("request", {}).get("object", {})
        with open("/app/fixtures.json", encoding="utf-8") as stream:
            fixture = json.load(stream)
        allowed, reason = verify_learning_update(fixture, obj)
        response = {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
                    "response": {"uid": uid, "allowed": allowed}}
        if not allowed:
            response["response"]["status"] = {"code": 403, "message": "SAF signed learning update: " + reason}
        body = json.dumps(response, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def verify_learning_update(fixture, obj):
    meta = obj.get("metadata", {})
    template = obj.get("spec", {}).get("template", {})
    labels = template.get("metadata", {}).get("labels", {})
    digest = "sha256:" + fixture["manifest_sha256"]
    artifact_digest = "sha256:" + fixture["artifact_sha256"]
    if meta.get("namespace") != fixture["namespace"]:
        return False, "Deployment namespace mismatch"
    if labels.get("saf-k8s.example/lifecycle-profile") != fixture["lifecycle_profile"]:
        return False, "continuous-learning profile missing"
    annotations = meta.get("annotations", {})
    if annotations.get("saf.example.test/model-digest") != digest:
        return False, "signed manifest digest mismatch"
    if annotations.get("saf.example.test/model-signature") != fixture["manifest_signature_base64"]:
        return False, "manifest signature mismatch"
    try:
        envelopes = json.loads(annotations["saf.example.test/attestations"])
    except (KeyError, json.JSONDecodeError):
        return False, "signed provenance materials missing"
    valid, reason = webhook.verify_artifact(fixture)
    if not valid:
        return False, reason
    valid, reason = webhook.verify_attestations(fixture, envelopes)
    if not valid:
        return False, reason
    if annotations.get("saf-k8s.example/update") != artifact_digest:
        return False, "release marker does not match the signed model bytes"
    volumes = template.get("spec", {}).get("volumes", [])
    source_ok = any(v.get("name") == "model-source"
                    and v.get("configMap", {}).get("name") == fixture["artifact_configmap"]
                    for v in volumes)
    if not source_ok:
        return False, "model source reference is not the digest-qualified fixture ConfigMap"
    init = template.get("spec", {}).get("initContainers", [])
    containers = template.get("spec", {}).get("containers", [])
    updater_ok = any(c.get("name") == "authorized-model-updater"
                     and c.get("image") == fixture["runtime_image"]
                     and any(m.get("name") == "model-source" and m.get("mountPath") == "/source"
                             for m in c.get("volumeMounts", []))
                     for c in init)
    monitor_ok = any(c.get("name") == "drift-monitor" and c.get("image") == fixture["runtime_image"]
                     and any(m.get("name") == "model-state" and m.get("mountPath") == "/model"
                             and m.get("readOnly") is True for m in c.get("volumeMounts", []))
                     for c in containers)
    reader_ok = any(c.get("name") == "model-reader" and c.get("image") == fixture["runtime_image"]
                    and any(m.get("name") == "model-state" and m.get("mountPath") == "/model"
                            and m.get("readOnly") is True for m in c.get("volumeMounts", []))
                    for c in containers)
    if not (updater_ok and monitor_ok and reader_ok):
        return False, "required updater, read-only consumer, or drift monitor is absent"
    return True, "exact signed model artifact and immutable source reference verified"


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
