"""Read the approved OCI publication and compare it to the separate scanner receipt."""
import hashlib
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

BASE = "http://model-registry:5000/v2/saf-fixture/models"
MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"
INDEX_TYPE = "application/vnd.oci.image.index.v1+json"
LINEAGE_TYPE = "application/vnd.saf.model-lineage.v1+json"
scanner = json.loads(Path("/scanner/scan.json").read_text())


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


opener = build_opener(ProxyHandler({}), NoRedirect())


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def get(path, accept=f"{MANIFEST_TYPE}, {INDEX_TYPE}"):
    request = Request(BASE + path, headers={"Accept": accept})
    try:
        with opener.open(request, timeout=6) as response:
            return response.status, response.read()
    except HTTPError as error:
        return error.code, error.read()


def manifest(reference):
    status, raw = get("/manifests/" + quote(reference, safe=":"))
    if status != 200:
        raise RuntimeError("approved publication was not readable")
    return raw, json.loads(raw)


approved_raw, approved = manifest("approved-model")
layer = approved["layers"][0]
status, model_bytes = get("/blobs/" + quote(layer["digest"], safe=":"), "application/octet-stream")
if status != 200:
    raise RuntimeError("approved model layer was not readable")

subject_digest = digest(approved_raw)
referrers_tag = subject_digest.replace(":", "-", 1)
index_raw, index = manifest(referrers_tag)
entries = [row for row in index.get("manifests", []) if row.get("artifactType") == LINEAGE_TYPE]
if len(entries) != 1:
    raise RuntimeError("approved publication did not have one lineage attachment")
attachment_raw, attachment = manifest(entries[0]["digest"])
if digest(attachment_raw) != entries[0]["digest"]:
    raise RuntimeError("lineage attachment digest was inconsistent")
if attachment.get("subject", {}).get("digest") != subject_digest:
    raise RuntimeError("lineage subject did not match approved publication")
blob = attachment["layers"][0]
status, lineage_raw = get("/blobs/" + quote(blob["digest"], safe=":"), "application/octet-stream")
if status != 200 or digest(lineage_raw) != blob["digest"]:
    raise RuntimeError("lineage payload digest was inconsistent")
lineage = json.loads(lineage_raw)

observed = {
    "scanner_receipt_passed": scanner.get("scan_result", {}).get("status") == "pass" and scanner.get("source_bytes_bounded") is True,
    "source_digest_matches_internal_layer": scanner.get("scan_result", {}).get("source_digest") == digest(model_bytes) == layer.get("digest"),
    "lineage_scan_matches_scanner_receipt": lineage.get("scan_result") == scanner.get("scan_result"),
    "lineage_source_digest_matches_scanner": lineage.get("source_digest") == scanner.get("scan_result", {}).get("source_digest"),
    "lineage_subject_matches_approved_manifest": lineage.get("subject_digest") == subject_digest,
    "approved_tag_and_subject_readable": True,
}
print(json.dumps(observed, sort_keys=True))
