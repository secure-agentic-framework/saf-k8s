"""Bounded Distribution API transfer component for the source cluster."""
import base64
from hashlib import sha256
from http.client import HTTPConnection
import json
import sys
import time

from verify_signature import verify as verify_rsa_sha256
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit

DESTINATION = "fixture-destination-registry.saf-test.svc"
PORT = 5000
REPOSITORY = "fixtures/model"
SOURCE_TAG = "approved"
MEDIA = "application/vnd.oci.image.manifest.v1+json"
STATEMENT = "com.example.saf.lineage.statement"
SIGNATURE = "com.example.saf.lineage.signature"
MAX_BODY = 2 * 1024 * 1024
MAX_TIMEOUT = 5
CHECK_TIME = datetime.now(timezone.utc)


def digest(data):
    return "sha256:" + sha256(data).hexdigest()


def _read_response(response):
    data = response.read(MAX_BODY + 1)
    if len(data) > MAX_BODY:
        raise ValueError("bounded registry response exceeded limit")
    return data


def request(host, port, method, path, body=None, media=None):
    if len(path) > 2048 or (body is not None and len(body) > MAX_BODY):
        raise ValueError("bounded registry request exceeded limit")
    connection = HTTPConnection(host, port, timeout=MAX_TIMEOUT)
    try:
        headers = {"Accept": MEDIA}
        if media:
            headers["Content-Type"] = media
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, _read_response(response), {
            key.lower(): value for key, value in response.getheaders()
        }
    finally:
        connection.close()


def read_source(source_host, reference=SOURCE_TAG, source_port=PORT):
    status, body, headers = request(
        source_host, source_port, "GET", f"/v2/{REPOSITORY}/manifests/{reference}")
    if status != 200 or headers.get("docker-content-digest") != digest(body):
        raise ValueError("source manifest status or Distribution digest header mismatch")
    manifest = json.loads(body)
    descriptor = manifest["config"]
    if descriptor.get("size", -1) > MAX_BODY:
        raise ValueError("source blob descriptor exceeds bounded fixture size")
    status, blob, blob_headers = request(
        source_host, source_port, "GET", f"/v2/{REPOSITORY}/blobs/{descriptor['digest']}")
    if status != 200 or len(blob) != descriptor["size"] or digest(blob) != descriptor["digest"]:
        raise ValueError("source blob bytes do not match their OCI descriptor")
    if blob_headers.get("docker-content-digest") not in (None, descriptor["digest"]):
        raise ValueError("source blob Distribution digest header mismatch")
    return body, manifest, blob, digest(body), descriptor["digest"]


def _lineage(manifest):
    annotations = manifest.get("annotations", {})
    statement_b64, signature_b64 = annotations.get(STATEMENT), annotations.get(SIGNATURE)
    if not statement_b64 or not signature_b64:
        return None, None, None
    statement_bytes = base64.b64decode(statement_b64, validate=True)
    signature_bytes = base64.b64decode(signature_b64, validate=True)
    return statement_bytes, signature_bytes, json.loads(statement_bytes)


def lineage_reason(manifest, blob_digest, source_digest, expected_source_digest, public_pem,
                   statement_b64, signature_b64):
    try:
        if not statement_b64 or not signature_b64:
            return "lineage-missing"
        statement_bytes = base64.b64decode(statement_b64, validate=True)
        signature_bytes = base64.b64decode(signature_b64, validate=True)
        statement = json.loads(statement_bytes)
    except (ValueError, TypeError, json.JSONDecodeError):
        return "lineage-malformed"
    if not verify_rsa_sha256(statement_bytes, signature_bytes, public_pem):
        return "signature-invalid"
    try:
        subject = statement["subject"][0]["digest"]["sha256"]
        created = datetime.fromisoformat(statement["predicate"]["saf_created_at"].replace("Z", "+00:00"))
        age = CHECK_TIME - created.astimezone(timezone.utc)
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        return "lineage-malformed"
    if subject != blob_digest.removeprefix("sha256:"):
        return "subject-mismatch"
    if not (0 <= age.total_seconds() <= 86400):
        return "lineage-stale"
    if statement.get("_type") != "https://in-toto.io/Statement/v1" or \
            statement.get("predicateType") != "https://slsa.dev/provenance/v1" or \
            statement.get("predicate", {}).get("saf_origin_cluster") != "fixture-training-cluster" or \
            statement.get("predicate", {}).get("saf_signing_identity") != "fixture://model-release-signer" or \
            statement.get("predicate", {}).get("saf_promotion_workflow") != "fixture-model-approved":
        return "lineage-policy-mismatch"
    if expected_source_digest != source_digest:
        return "source-manifest-digest-mismatch"
    return "allowed"


def _upload_blob(blob):
    prefix = f"/v2/{REPOSITORY}/"
    status, _, headers = request(DESTINATION, PORT, "POST", prefix + "blobs/uploads/", b"")
    if status != 202 or "location" not in headers:
        raise RuntimeError("destination refused upload initialization")
    location = urlsplit(headers["location"])
    if not location.path.startswith(prefix + "blobs/uploads/"):
        raise RuntimeError("destination returned an unexpected upload path")
    query = urlencode([*parse_qsl(location.query), ("digest", digest(blob))])
    status, _, _ = request(DESTINATION, PORT, "PUT", location.path + "?" + query,
                           blob, "application/octet-stream")
    if status != 201:
        raise RuntimeError("destination refused blob bytes")


def seed_source(proposal):
    statement_b64 = proposal["statement_b64"]
    signature_b64 = proposal["signature_b64"]
    statement_bytes = base64.b64decode(statement_b64, validate=True)
    signature_bytes = base64.b64decode(signature_b64, validate=True)
    blob = json.dumps({"executable": False, "name": "fixture-linear-model",
                       "version": "1.0.0", "weights": "synthetic-placeholder"},
                      sort_keys=True, separators=(",", ":")).encode()
    manifest = {
        "schemaVersion": 2, "mediaType": MEDIA,
        "artifactType": "application/vnd.saf.fixture.model-metadata.v1+json",
        "config": {"mediaType": "application/vnd.saf.fixture.model-metadata.v1+json",
                   "digest": digest(blob), "size": len(blob)},
        "layers": [],
        "annotations": {STATEMENT: statement_b64, SIGNATURE: signature_b64},
    }
    if not verify_rsa_sha256(statement_bytes, signature_bytes,
                             base64.b64decode(proposal["public_pem_b64"], validate=True)):
        raise ValueError("seed lineage signature did not verify")
    _upload_blob_to(proposal["source_host"], blob, PORT)
    body = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    status, _, _ = request(proposal["source_host"], PORT, "PUT",
                           f"/v2/{REPOSITORY}/manifests/{SOURCE_TAG}", body, MEDIA)
    if status != 201:
        raise RuntimeError("source registry refused OCI manifest")
    return {"source_digest": digest(body), "blob_digest": digest(blob)}


def _upload_blob_to(host, blob, port=PORT):
    prefix = f"/v2/{REPOSITORY}/"
    status, _, headers = request(host, port, "POST", prefix + "blobs/uploads/", b"")
    if status != 202 or "location" not in headers:
        raise RuntimeError("source refused upload initialization")
    location = urlsplit(headers["location"])
    if not location.path.startswith(prefix + "blobs/uploads/"):
        raise RuntimeError("source returned an unexpected upload path")
    query = urlencode([*parse_qsl(location.query), ("digest", digest(blob))])
    status, _, _ = request(host, port, "PUT", location.path + "?" + query,
                           blob, "application/octet-stream")
    if status != 201:
        raise RuntimeError("source refused blob bytes")


def source_route():
    with open("/fixture/source-route.json", encoding="utf-8") as route:
        info = json.load(route)
    return info["host"], info["port"]


def transfer(proposal):
    host, port = source_route()
    source_body, manifest, blob, source_digest, blob_digest = read_source(host, source_port=port)
    mode, tag = proposal.get("mode"), proposal.get("tag")
    refused_tags = {"refuse-missing", "refuse-stale", "refuse-subject",
                    "refuse-source-digest", "refuse-signature"}
    if tag not in {"baseline", "preserved"} | refused_tags:
        return {"decision": "tag-not-allowed", "written": False}
    if mode == "off":
        # Same model bytes are transferred through the Distribution API; lineage is omitted.
        baseline_manifest = dict(manifest)
        baseline_manifest["annotations"] = {
            key: value for key, value in manifest.get("annotations", {}).items()
            if key not in {STATEMENT, SIGNATURE}
        }
        manifest_bytes = json.dumps(baseline_manifest, sort_keys=True,
                                    separators=(",", ":")).encode()
        reason = "unchecked-baseline"
    elif mode == "on":
        with open("/fixture/approved-public.pem", "rb") as key_file:
            public_pem = key_file.read(16 * 1024 + 1)
        if len(public_pem) > 16 * 1024:
            raise ValueError("approved verifier material exceeds limit")
        reason = lineage_reason(manifest, blob_digest, source_digest,
                                proposal.get("expected_source_digest"), public_pem,
                                proposal.get("statement_b64"), proposal.get("signature_b64"))
        if reason != "allowed":
            return {"decision": reason, "written": False}
        try:
            proposed = base64.b64decode(proposal["statement_b64"], validate=True)
            proposed_sig = base64.b64decode(proposal["signature_b64"], validate=True)
            source_stmt, source_sig, _ = _lineage(manifest)
        except (KeyError, ValueError, TypeError):
            return {"decision": "lineage-malformed", "written": False}
        if proposed != source_stmt or proposed_sig != source_sig:
            return {"decision": "source-lineage-mismatch", "written": False}
        manifest_bytes = source_body
    else:
        return {"decision": "mode-not-allowed", "written": False}
    _upload_blob(blob)
    status, _, _ = request(DESTINATION, PORT, "PUT",
                           f"/v2/{REPOSITORY}/manifests/{tag}", manifest_bytes, MEDIA)
    if status != 201:
        raise RuntimeError("destination refused OCI manifest")
    return {"decision": reason, "written": True,
            "source_digest": source_digest, "destination_digest": digest(manifest_bytes),
            "blob_digest": blob_digest}


if __name__ == "__main__":
    operation = sys.argv[1]
    if operation == "wait-source":
        host, port = source_route()
        deadline = time.monotonic() + 20
        ready = False
        while time.monotonic() < deadline:
            try:
                ready = request(host, port, "GET", "/v2/")[0] == 200
            except (ConnectionRefusedError, TimeoutError):
                pass
            if ready:
                break
            time.sleep(0.25)
        result = {"ready": ready}
    elif operation == "seed":
        result = seed_source(json.load(sys.stdin))
    elif operation == "transfer":
        result = transfer(json.load(sys.stdin))
    elif operation == "inspect":
        raw, manifest, blob, manifest_digest, blob_digest = read_source(sys.argv[2], source_port=PORT)
        statement_b64, signature_b64 = manifest.get("annotations", {}).get(STATEMENT), \
            manifest.get("annotations", {}).get(SIGNATURE)
        result = {"status": 200, "manifest_digest": manifest_digest,
                  "manifest_bytes_b64": base64.b64encode(raw).decode(),
                  "blob_digest": blob_digest,
                  "blob_bytes_b64": base64.b64encode(blob).decode(),
                  "statement_b64": statement_b64, "signature_b64": signature_b64,
                  "blob_size": len(blob)}
    else:
        raise SystemExit("unknown operation")
    print(json.dumps(result, sort_keys=True))
