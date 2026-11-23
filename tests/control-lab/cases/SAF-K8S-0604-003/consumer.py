"""Retrieve a selected SBOM from the case-owned OCI registry and verify its identity."""
import hashlib
from http.client import HTTPSConnection
import json
from pathlib import Path
import re
import ssl
import sys

MANIFEST = "application/vnd.oci.image.manifest.v1+json"
INDEX = "application/vnd.oci.image.index.v1+json"
SBOM = "application/vnd.cyclonedx+json"
LIMIT = 1024 * 1024
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class VerificationError(ValueError):
    pass


def digest(payload):
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def get(host, port, ca, path, accepted, authorization):
    connection = HTTPSConnection(host, port, timeout=8, context=ssl.create_default_context(cafile=ca))
    try:
        headers = {"Accept": accepted}
        if authorization:
            headers["Authorization"] = authorization
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read(LIMIT + 1)
        if len(body) > LIMIT:
            raise VerificationError("response-too-large")
        return response.status, body
    finally:
        connection.close()


def inventory_descriptors(fetch, repository, subject):
    base = f"/v2/{repository}"
    status, body = fetch(f"{base}/referrers/{subject}", INDEX)
    path = "api"
    if status == 404:
        tag = subject.replace(":", "-", 1)
        status, body = fetch(f"{base}/manifests/{tag}", INDEX)
        path = "tag"
    if status == 404:
        return path, []
    if status != 200:
        raise VerificationError("discovery-failed")
    parsed = json.loads(body)
    if parsed.get("mediaType") != INDEX or not isinstance(parsed.get("manifests"), list):
        raise VerificationError("invalid-discovery-index")
    return path, [row for row in parsed["manifests"] if row.get("artifactType") == SBOM]


def valid_bytes(fetched, descriptor):
    return digest(fetched) == descriptor.get("digest") and len(fetched) == descriptor.get("size")


def verify(fetch, repository, subject, candidate, approved):
    base = f"/v2/{repository}"
    artifact = candidate.get("digest", "")
    if not DIGEST.fullmatch(artifact) or candidate.get("mediaType") != MANIFEST:
        raise VerificationError("invalid-manifest-descriptor")
    status, content = fetch(f"{base}/manifests/{artifact}", MANIFEST)
    if status != 200 or not valid_bytes(content, candidate):
        raise VerificationError("manifest-bytes-mismatch")
    manifest = json.loads(content)
    link = manifest.get("subject", {})
    if link.get("digest") != subject:
        raise VerificationError("subject-mismatch")
    status, image = fetch(f"{base}/manifests/{subject}", MANIFEST)
    if status != 200 or not valid_bytes(image, link) or link.get("mediaType") != MANIFEST:
        raise VerificationError("subject-bytes-mismatch")
    if manifest.get("artifactType") != SBOM or len(manifest.get("layers", [])) != 1:
        raise VerificationError("unexpected-artifact-type")
    layer, = manifest["layers"]
    blob = layer.get("digest", "")
    if not DIGEST.fullmatch(blob) or layer.get("mediaType") != SBOM:
        raise VerificationError("invalid-bom-descriptor")
    status, contents = fetch(f"{base}/blobs/{blob}", SBOM)
    if status != 200 or not valid_bytes(contents, layer):
        raise VerificationError("bom-bytes-mismatch")
    bom = json.loads(contents)
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.7":
        raise VerificationError("unexpected-bom-format")
    if artifact != approved:
        raise VerificationError("attachment-not-approved")
    return [component["name"] for component in bom["components"]]


def run():
    with open("/fixture/plan.json", encoding="utf-8") as file:
        plan = json.load(file)

    access_file = Path("/access/authorization")
    auth = access_file.read_text() if access_file.is_file() else ""

    def fetch(path, accepted):
        return get(plan["host"], 5000, "/fixture/ca.crt", path, accepted, auth)

    selected, comparison = plan["target"], plan["comparison"]
    if not DIGEST.fullmatch(selected) or not DIGEST.fullmatch(comparison):
        raise VerificationError("invalid-pinned-subject")
    mode, candidates = inventory_descriptors(fetch, plan["repository"], selected)
    _, others = inventory_descriptors(fetch, plan["repository"], comparison)
    by_digest = {item["digest"]: item for item in candidates}
    good = by_digest[plan["approved"]]
    not_approved = by_digest[plan["unapproved"]]
    other, = others
    results = {"discovery": mode, "exact_subject_components": verify(
        fetch, plan["repository"], selected, good, plan["approved"]
    )}

    def wrong_blob(path, accepted):
        status, contents = fetch(path, accepted)
        if "/blobs/" in path and status == 200:
            contents = b" " + contents[1:]
        return status, contents

    for label, getter, candidate in (
        ("different_subject", fetch, other),
        ("unapproved_artifact", fetch, not_approved),
        ("wrong_blob_bytes", wrong_blob, good),
    ):
        try:
            verify(getter, plan["repository"], selected, candidate, plan["approved"])
        except VerificationError as error:
            results[label] = str(error)
        else:
            results[label] = "unexpected-acceptance"
    print(json.dumps(results, sort_keys=True))


if __name__ == "__main__":
    sys.exit(run())
