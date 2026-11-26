"""Case-owned signer: authenticate projected producer identity before signing a PVC receipt."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import hashlib
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.request

import training_fixture as fixture
from lineage_crypto import EphemeralSigner
from signature_format import canonical, public_key_id

NAMESPACE = "saf-test"
AUDIENCE = "https://lineage-signer.saf.invalid"
API = "https://kubernetes.default.svc"
TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
TRUST_NAME = "fixture-training-provenance-signer-trust"
EXPECTED_USERS = {
    "source": f"system:serviceaccount:{NAMESPACE}:fixture-lineage-source",
    "transform": f"system:serviceaccount:{NAMESPACE}:fixture-lineage-transform",
    "training": f"system:serviceaccount:{NAMESPACE}:fixture-lineage-training",
}
PATHS = {
    "source": ("/source/ingested.bin", "/source-receipt/source.json"),
    "transform": ("/transformed/dataset.bin", "/transform-receipt/transformation.json"),
    "training": ("/artifact/governed/model.json", "/artifact/governed/training-receipt.json"),
}


def _api(path, body):
    request = urllib.request.Request(
        API + path, data=json.dumps(body, sort_keys=True).encode(), method="POST",
        headers={"Authorization": "Bearer " + TOKEN_PATH.read_text().strip(),
                 "Content-Type": "application/json"})
    context = ssl.create_default_context(cafile=CA_PATH)
    try:
        with urllib.request.urlopen(request, context=context, timeout=5) as response:
            return response.status, json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        raise RuntimeError("fixture signer API request failed") from None


def _review(token):
    status, result = _api("/apis/authentication.k8s.io/v1/tokenreviews", {
        "apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
        "spec": {"token": token, "audiences": [AUDIENCE]}})
    if status != 201:
        raise RuntimeError("fixture TokenReview failed")
    value = result.get("status", {})
    return (value.get("authenticated") is True,
            value.get("user", {}).get("username"),
            sorted(value.get("audiences", [])))


def _read_receipt(stage):
    data_path, receipt_path = PATHS[stage]
    data = Path(data_path).read_bytes()
    receipt_bytes = Path(receipt_path).read_bytes()
    receipt = json.loads(receipt_bytes)
    digest = hashlib.sha256
    if stage == "source":
        valid = data == fixture.SOURCE and receipt == {
            "source_id": fixture.SOURCE_ID, "source_sha256": digest(data).hexdigest(),
            "bytes": len(data), "approval_ref": "synthetic-approval-v1"}
    elif stage == "transform":
        source = Path("/source/ingested.bin").read_bytes()
        source_receipt = json.loads(Path("/source-receipt/source.json").read_bytes())
        valid = (source == fixture.SOURCE and data == fixture.TRANSFORMED and receipt == {
            "transform_id": fixture.TRANSFORM_ID,
            "source_sha256": digest(source).hexdigest(),
            "output_sha256": digest(data).hexdigest(), "output_bytes": len(data)}
            and source_receipt.get("source_sha256") == digest(source).hexdigest())
    else:
        model = json.loads(data)
        training = json.loads(Path("/artifact/governed/training-receipt.json").read_bytes())
        source = Path("/source/ingested.bin").read_bytes()
        transformed = Path("/transformed/dataset.bin").read_bytes()
        sr = Path("/source-receipt/source.json").read_bytes()
        tr = Path("/transform-receipt/transformation.json").read_bytes()
        valid = model.get("source_sha256") == digest(source).hexdigest() == fixture.SOURCE_DIGEST
        valid = valid and model.get("transformed_sha256") == digest(transformed).hexdigest() == fixture.TRANSFORMED_DIGEST
        valid = valid and training.get("artifact_sha256") == digest(data).hexdigest()
        valid = valid and training.get("source_receipt_sha256") == digest(sr).hexdigest()
        valid = valid and training.get("transformation_receipt_sha256") == digest(tr).hexdigest()
        valid = valid and training.get("approval_id") == "synthetic-approval-v1"
        receipt = training
    if not valid:
        raise ValueError("fixture receipt does not match the approved bytes")
    return receipt


def _write_trust(signer):
    body = {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": TRUST_NAME, "namespace": NAMESPACE},
            "immutable": True,
            "data": {"public.pem": signer.public_pem,
                     "key-id": public_key_id(signer.public_pem)}}
    request = urllib.request.Request(
        API + f"/api/v1/namespaces/{NAMESPACE}/configmaps",
        data=json.dumps(body, sort_keys=True).encode(), method="POST",
        headers={"Authorization": "Bearer " + TOKEN_PATH.read_text().strip(),
                 "Content-Type": "application/json"})
    context = ssl.create_default_context(cafile=CA_PATH)
    try:
        with urllib.request.urlopen(request, context=context, timeout=5) as response:
            return response.status == 201
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return False


class Handler(BaseHTTPRequestHandler):
    signer = None
    ready = False

    def log_message(self, *_args):
        return

    def _reply(self, status, value):
        body = json.dumps(value, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/readyz" and self.ready:
            self._reply(200, {"ready": True})
        else:
            self._reply(404, {"ready": False})

    def do_POST(self):
        stage = self.path.removeprefix("/sign/")
        if stage not in EXPECTED_USERS or not self.ready:
            self._reply(404, {"signed": False})
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length > 256 or length < 0:
            self._reply(413, {"signed": False})
            return
        self.rfile.read(length)
        token = self.headers.get("Authorization", "")
        if not token.startswith("Bearer "):
            self._reply(401, {"signed": False})
            return
        try:
            auth = _review(token[7:])
            user = EXPECTED_USERS[stage]
            if auth != (True, user, [AUDIENCE]):
                self._reply(403, {"signed": False})
                return
            receipt = _read_receipt(stage)
            envelope = {"schema": "training-lineage-receipt/v1", "stage": stage,
                        "producer": user, "receipt": receipt}
            signature = self.signer.sign(canonical(envelope))
            self._reply(200, {"signed": True, "envelope": envelope,
                              "signature": base64.b64encode(signature).decode("ascii"),
                              "key_id": public_key_id(self.signer.public_pem)})
        except (KeyError, OSError, ValueError, RuntimeError, json.JSONDecodeError):
            self._reply(409, {"signed": False})


def main():
    signer = EphemeralSigner()
    Handler.signer = signer
    server = None
    try:
        server = HTTPServer(("0.0.0.0", 8080), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain("/tls-server/tls.crt", "/tls-server/tls.key")
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        Handler.ready = _write_trust(signer)
        if not Handler.ready:
            raise SystemExit("fixture signer initialization failed")
        print("READY", flush=True)
        server.serve_forever()
    finally:
        Handler.ready = False
        if server is not None:
            server.server_close()
        signer.close()


if __name__ == "__main__":
    main()
