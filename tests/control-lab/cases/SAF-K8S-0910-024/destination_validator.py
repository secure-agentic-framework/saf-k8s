"""Independent peer-side OCI and provenance readback validator."""
import base64
from hashlib import sha256
from http.client import HTTPConnection
import json
import sys

from verify_signature import verify as verify_signature

HOST = "fixture-destination-registry.saf-test.svc"
PORT = 5000
REPO = "fixtures/model"
MEDIA = "application/vnd.oci.image.manifest.v1+json"
STATEMENT = "com.example.saf.lineage.statement"
SIGNATURE = "com.example.saf.lineage.signature"
MAX_BODY = 2 * 1024 * 1024


def digest(data):
    return "sha256:" + sha256(data).hexdigest()


def get(path):
    if len(path) > 2048:
        raise ValueError("bounded path exceeded")
    connection = HTTPConnection(HOST, PORT, timeout=5)
    try:
        connection.request("GET", path, headers={"Accept": MEDIA})
        response = connection.getresponse()
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError("bounded readback exceeded")
        return response.status, body, {k.lower(): v for k, v in response.getheaders()}
    finally:
        connection.close()


def inspect(tag, expected):
    status, body, headers = get(f"/v2/{REPO}/manifests/{tag}")
    if status != 200:
        return {"status": status, "checks": {"manifest_present": False}}
    actual_manifest_digest = digest(body)
    manifest = json.loads(body)
    descriptor = manifest["config"]
    if descriptor.get("size", -1) > MAX_BODY:
        raise ValueError("blob descriptor exceeds validator limit")
    blob_status, blob, blob_headers = get(f"/v2/{REPO}/blobs/{descriptor['digest']}")
    actual_blob_digest = digest(blob) if blob_status == 200 else None
    annotations = manifest.get("annotations", {})
    statement_b64, signature_b64 = annotations.get(STATEMENT), annotations.get(SIGNATURE)
    checks = {
        "manifest_present": True,
        "manifest_body_hash_matches_header": headers.get("docker-content-digest") == actual_manifest_digest,
        "manifest_bytes_equal_source": body == base64.b64decode(expected["manifest_b64"], validate=True),
        "blob_readback_present": blob_status == 200,
        "blob_bytes_match_descriptor": blob_status == 200 and actual_blob_digest == descriptor["digest"],
        "blob_bytes_equal_source": blob_status == 200 and blob == base64.b64decode(
            expected["blob_bytes_b64"], validate=True),
        "blob_digest_equal_source": actual_blob_digest == expected["blob_digest"],
        "blob_length_matches_descriptor": blob_status == 200 and len(blob) == descriptor["size"],
        "blob_header_matches_bytes": blob_headers.get("docker-content-digest") in
            (None, actual_blob_digest),
    }
    if expected["mode"] == "on":
        try:
            statement_bytes = base64.b64decode(statement_b64, validate=True)
            signature_bytes = base64.b64decode(signature_b64, validate=True)
            source_statement = base64.b64decode(expected["statement_b64"], validate=True)
            source_signature = base64.b64decode(expected["signature_b64"], validate=True)
            public_pem = open("/fixture/approved-public.pem", "rb").read(16 * 1024 + 1)
            parsed = json.loads(statement_bytes)
            checks["lineage_bytes_equal_source"] = (
                statement_bytes == source_statement and signature_bytes == source_signature)
            checks["lineage_signature_check_passed_from_readback_bytes"] = verify_signature(
                statement_bytes, signature_bytes, public_pem)
            checks["lineage_subject_binds_blob"] = (
                parsed["subject"][0]["digest"]["sha256"] == actual_blob_digest.removeprefix("sha256:"))
            checks["lineage_policy_fields_match"] = (
                parsed.get("_type") == "https://in-toto.io/Statement/v1" and
                parsed.get("predicateType") == "https://slsa.dev/provenance/v1" and
                parsed["predicate"].get("saf_origin_cluster") == "fixture-training-cluster" and
                parsed["predicate"].get("saf_signing_identity") == "fixture://model-release-signer" and
                parsed["predicate"].get("saf_promotion_workflow") == "fixture-model-approved")
        except (KeyError, ValueError, TypeError, IndexError, AttributeError):
            checks.update({"lineage_bytes_equal_source": False,
                           "lineage_signature_check_passed_from_readback_bytes": False,
                           "lineage_subject_binds_blob": False,
                           "lineage_policy_fields_match": False})
    else:
        checks["required_lineage_omitted"] = not statement_b64 and not signature_b64
    return {"status": status, "checks": checks}


if __name__ == "__main__":
    command, tag = sys.argv[1], sys.argv[2]
    if command == "inspect":
        output = inspect(tag, json.load(sys.stdin))
    elif command == "absent":
        status, _, _ = get(f"/v2/{REPO}/manifests/{tag}")
        output = {"status": status, "checks": {"destination_tag_absent": status == 404}}
    else:
        raise SystemExit("unknown operation")
    print(json.dumps(output, sort_keys=True))
