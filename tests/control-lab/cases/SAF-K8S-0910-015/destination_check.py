"""Destination-side Distribution readback and signature check for inert metadata."""
import base64
from hashlib import sha256
from http.client import HTTPConnection
import json
import sys

from verify_signature import verify

HOST = "fixture-destination-registry.saf-test.svc"
PORT = 5000
REPO = "fixtures/model"
MEDIA = "application/vnd.oci.image.manifest.v1+json"
STATEMENT = "com.example.saf.lineage.statement"
SIGNATURE = "com.example.saf.lineage.signature"
MAX_BODY = 2 * 1024 * 1024
EXPECTED_REFERENCE = "copied"


def digest(data):
    return "sha256:" + sha256(data).hexdigest()


def get(path):
    if len(path) > 2048:
        raise ValueError("bounded registry path exceeded")
    conn = HTTPConnection(HOST, PORT, timeout=5)
    try:
        conn.request("GET", path, headers={"Accept": MEDIA})
        response = conn.getresponse()
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError("bounded registry body exceeded")
        return response.status, body, {k.lower(): v for k, v in response.getheaders()}
    finally:
        conn.close()


def inspect(tag, expected, public_pem):
    status, raw, headers = get(f"/v2/{REPO}/manifests/{tag}")
    checks = {"manifest_present": status == 200}
    if status != 200:
        return {"status": status, "checks": checks}
    manifest_hash = digest(raw)
    manifest = json.loads(raw)
    descriptor = manifest["config"]
    blob_status, blob, blob_headers = get(f"/v2/{REPO}/blobs/{descriptor['digest']}")
    blob_hash = digest(blob) if blob_status == 200 else ""
    annotations = manifest.get("annotations", {})
    try:
        statement = base64.b64decode(annotations[STATEMENT], validate=True)
        signature = base64.b64decode(annotations[SIGNATURE], validate=True)
        parsed = json.loads(statement)
        subject = parsed["subject"][0]["digest"]["sha256"]
    except (KeyError, ValueError, TypeError, IndexError):
        statement, signature, subject = b"", b"", ""
    checks.update({
        "manifest_reference_is_expected": tag == EXPECTED_REFERENCE == expected["reference"],
        "manifest_digest_matches_source_claim": manifest_hash == expected["manifest_digest"],
        "manifest_digest_header_matches_readback": headers.get("docker-content-digest") == manifest_hash,
        "blob_readback_present": blob_status == 200,
        "blob_digest_matches_descriptor": blob_status == 200 and blob_hash == descriptor.get("digest"),
        "blob_digest_matches_signed_subject": blob_hash.removeprefix("sha256:") == subject,
        "blob_bytes_match_source": base64.b64decode(expected["blob_b64"], validate=True) == blob,
        "blob_size_matches_descriptor": blob_status == 200 and len(blob) == descriptor.get("size"),
        "blob_header_matches_bytes": blob_headers.get("docker-content-digest") in (None, blob_hash),
        "signature_valid_over_readback_statement": bool(statement and signature) and verify(statement, signature, public_pem),
        "statement_bytes_match_source": statement == base64.b64decode(expected["statement_b64"], validate=True),
        "signature_bytes_match_source": signature == base64.b64decode(expected["signature_b64"], validate=True),
        "artifact_is_inert_fixture_metadata": manifest.get("artifactType") == "application/vnd.saf.fixture.model-metadata.v1+json"
            and not json.loads(blob).get("executable", True),
    })
    return {"status": status, "manifest_digest": manifest_hash, "blob_digest": blob_hash,
            "reference": tag, "checks": checks}


if __name__ == "__main__":
    operation = sys.argv[1]
    public = open("/fixture/approved-public.pem", "rb").read(16385)
    if len(public) > 16384:
        raise SystemExit("trusted public key exceeds bound")
    if operation == "inspect":
        output = inspect(sys.argv[2], json.load(sys.stdin), public)
    elif operation == "consume":
        action = json.loads(sys.argv[3])
        status, manifest_raw, _ = get(f"/v2/{REPO}/manifests/{sys.argv[2]}")
        manifest = json.loads(manifest_raw) if status == 200 else {}
        descriptor = manifest.get("config", {})
        blob_status, blob, _ = get(f"/v2/{REPO}/blobs/{descriptor.get('digest', '')}") if descriptor else (404, b"", {})
        actual_digest = "sha256:" + sha256(blob).hexdigest() if blob_status == 200 else ""
        metadata = json.loads(blob) if blob else {}
        output = {"consumed": (status == 200 and blob_status == 200 and actual_digest == action["expected_blob_digest"]
                               and digest(manifest_raw) == action["expected_manifest_digest"]
                               and metadata.get("executable") is False),
                  "reference": sys.argv[2], "blob_digest": actual_digest,
                  "artifact": metadata.get("weights", ""), "action": action["action"]}
    else:
        raise SystemExit("unknown operation")
    print(json.dumps(output, sort_keys=True))
