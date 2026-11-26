"""Small fixture-only HTTPS admission verifier for SAF-K8S-0905-009."""
import base64
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
from urllib.parse import urlsplit


def _der_item(data, offset=0):
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7f
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    return tag, data[offset:offset + length], offset + length


def _rsa_numbers(pem):
    encoded = "".join(line for line in pem.splitlines() if not line.startswith("-----"))
    der = base64.b64decode(encoded, validate=True)
    _, outer, _ = _der_item(der)
    _, _, after_algorithm = _der_item(outer)
    _, bit_string, _ = _der_item(outer, after_algorithm)
    _, rsa_sequence, _ = _der_item(bit_string, 1)
    _, modulus, cursor = _der_item(rsa_sequence)
    _, exponent, _ = _der_item(rsa_sequence, cursor)
    return int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")


def _rsa_sha256_verify(public_pem, message, signature_b64):
    modulus, exponent = _rsa_numbers(public_pem)
    signature = base64.b64decode(signature_b64, validate=True)
    width = (modulus.bit_length() + 7) // 8
    if len(signature) != width or int.from_bytes(signature, "big") >= modulus:
        return False
    decoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(width, "big")
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(message).digest()
    padding = width - len(digest_info) - 3
    expected = b"\x00\x01" + b"\xff" * padding + b"\x00" + digest_info
    return padding >= 8 and decoded == expected


def _dsse_pae(payload_type, payload):
    type_bytes = payload_type.encode("utf-8")
    return (b"DSSEv1 " + str(len(type_bytes)).encode() + b" " + type_bytes + b" "
            + str(len(payload)).encode() + b" " + payload)


def verify_attestations(fixture, envelopes):
    if not isinstance(envelopes, list) or len(envelopes) != 2:
        return False, "attestation set must contain two materials"
    predicates = []
    for envelope in envelopes:
        if envelope.get("payloadType") != "application/vnd.in-toto+json":
            return False, "unsupported attestation payload type"
        payload = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(payload)
        if statement.get("_type") != "https://in-toto.io/Statement/v1":
            return False, "attestation is not an in-toto Statement v1"
        subjects = statement.get("subject", [])
        if subjects != [{"name": "oci://saf.example.test/models/inert-fixture",
                         "digest": {"sha256": fixture["artifact_sha256"]}}]:
            return False, "attestation subject digest does not match the fixture artifact"
        signatures = envelope.get("signatures", [])
        if len(signatures) != 1 or signatures[0].get("keyid") != "saf-fixed-fixture-rsa-1":
            return False, "attestation signer is not the fixed fixture signer"
        if not _rsa_sha256_verify(fixture["public_key_pem"],
                                  _dsse_pae(envelope["payloadType"], payload),
                                  signatures[0]["sig"]):
            return False, "in-toto DSSE signature is invalid"
        predicates.append(statement.get("predicateType"))
    if predicates != sorted(fixture["required_predicate_types"]):
        return False, "approval and provenance materials are missing, duplicated, or unsorted"
    return True, "two sorted signed in-toto materials match the artifact digest"


def verify_artifact(fixture):
    artifact = base64.b64decode(fixture["artifact"], validate=True)
    config = base64.b64decode(fixture["config"], validate=True)
    manifest_bytes = base64.b64decode(fixture["manifest_canonical_json_base64"], validate=True)
    manifest = json.loads(manifest_bytes)
    if json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode() != manifest_bytes:
        return False, "OCI manifest bytes are not canonical fixture bytes"
    if hashlib.sha256(manifest_bytes).hexdigest() != fixture["manifest_sha256"]:
        return False, "OCI manifest digest mismatch"
    if hashlib.sha256(artifact).hexdigest() != fixture["artifact_sha256"]:
        return False, "artifact layer digest mismatch"
    if (manifest["config"]["digest"] != "sha256:" + hashlib.sha256(config).hexdigest()
            or manifest["config"]["size"] != len(config)):
        return False, "OCI config descriptor digest mismatch"
    if manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
        return False, "unsupported OCI manifest media type"
    layer = manifest.get("layers", [{}])[0]
    if (layer.get("digest") != "sha256:" + fixture["artifact_sha256"]
            or layer.get("size") != len(artifact)):
        return False, "OCI layer descriptor does not match artifact bytes"
    if not _rsa_sha256_verify(fixture["public_key_pem"], fixture["manifest_sha256"].encode(),
                              fixture["manifest_signature_base64"]):
        return False, "OCI manifest signature is invalid"
    return True, "signed OCI manifest and layer digests match exact fixture bytes"


def verify_deployment(fixture, obj):
    annotations = obj.get("metadata", {}).get("annotations", {})
    expected_image = "saf.example.test/models/inert-fixture@sha256:" + fixture["manifest_sha256"]
    containers = obj.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    spec = obj.get("spec", {})
    template_spec = spec.get("template", {}).get("spec", {})
    if (spec.get("replicas") != 0 or template_spec.get("initContainers")
            or len(containers) != 1 or containers[0].get("name") != "inert-model-fixture"
            or containers[0].get("image") != expected_image):
        return False, "Deployment image reference is not the verified inert model artifact or fixture is not zero-replica"
    digest = "sha256:" + fixture["manifest_sha256"]
    if annotations.get("saf.example.test/model-digest") != digest:
        return False, "model digest is absent or does not match the signed OCI manifest"
    if annotations.get("saf.example.test/model-signature") != fixture["manifest_signature_base64"]:
        return False, "model signature is absent or does not match the fixed signer"
    try:
        envelopes = json.loads(annotations["saf.example.test/attestations"])
    except (KeyError, json.JSONDecodeError):
        return False, "approval and provenance materials are absent or malformed"
    valid, reason = verify_attestations(fixture, envelopes)
    if not valid:
        return False, reason
    valid, reason = verify_artifact(fixture)
    if not valid:
        return False, reason
    return True, "fixed signed artifact and both in-toto materials verified"


class Handler(BaseHTTPRequestHandler):
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
        fixture_path = os.environ.get("FIXTURES", "/app/fixtures.json")
        with open(fixture_path, encoding="utf-8") as stream:
            fixture = json.load(stream)
        allowed, message = verify_deployment(fixture, obj)
        response = {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
                    "response": {"uid": uid, "allowed": allowed}}
        if not allowed:
            response["response"]["status"] = {"code": 403, "message": "SAF fixture verifier: " + message}
        data = json.dumps(response, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, _format, *_args):
        return


def main():
    server = HTTPServer(("0.0.0.0", 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
