"""Synthetic external-model intake through a case-owned OCI registry endpoint."""
from datetime import date
import hashlib
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit
from urllib.request import Request, urlopen

BASE = "http://model-registry:5000"
REPO_PATH = "/v2/saf-fixture/models"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_EMPTY = "application/vnd.oci.empty.v1+json"
LINEAGE_TYPE = "application/vnd.saf.model-lineage.v1+json"
FIXTURE = b'{"kind":"inert-synthetic-model","format":"fixture-v1"}'
CONFIG = b'{}'
SCAN_ID = "fixture-json-structure-v1"
MEASURED_DATE = "2026-04-17"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def descriptor(media, raw):
    return {"mediaType": media, "digest": digest(raw), "size": len(raw)}


def request(method, path, body=None, media=None, expected=(200,)):
    url = BASE + REPO_PATH + path
    if urlsplit(url).netloc != urlsplit(BASE).netloc:
        raise RuntimeError("non-case-owned endpoint")
    headers = {"Accept": f"{OCI_MANIFEST}, {OCI_INDEX}"}
    if media:
        headers["Content-Type"] = media
    try:
        with urlopen(Request(url, data=body, headers=headers, method=method), timeout=8) as response:
            status, response_headers, raw = response.status, response.headers, response.read()
    except HTTPError as response:
        status, response_headers, raw = response.code, response.headers, response.read()
    if status not in expected:
        raise RuntimeError(f"registry {method} returned unexpected status {status}")
    return status, response_headers, raw


def upload_blob(raw):
    _, headers, _ = request("POST", "/blobs/uploads/", b"", expected=(202,))
    location = urljoin(BASE, headers["Location"])
    if urlsplit(location).netloc != urlsplit(BASE).netloc:
        raise RuntimeError("registry returned a non-case-owned upload location")
    upload_path = urlsplit(location).path
    if not upload_path.startswith(REPO_PATH + "/blobs/uploads/"):
        raise RuntimeError("registry returned an unexpected upload path")
    query = urlencode(parse_qsl(urlsplit(location).query, keep_blank_values=True)
                      + [("digest", digest(raw))])
    path = upload_path[len(REPO_PATH):] + "?" + query
    request("PUT", path, raw, "application/octet-stream", expected=(201,))


def put_manifest(reference, raw, media=OCI_MANIFEST):
    return request("PUT", "/manifests/" + quote(reference, safe=":"), raw, media, expected=(201,))[0]


def fetch_manifest(reference):
    return request("GET", "/manifests/" + quote(reference, safe=":"), expected=(200, 404))


def model_manifest():
    return CONFIG, canonical({"schemaVersion": 2, "mediaType": OCI_MANIFEST,
                              "artifactType": "application/vnd.saf.fixture-model.v1+json",
                              "config": descriptor(OCI_EMPTY, CONFIG),
                              "layers": [descriptor("application/json", FIXTURE)]})


def scan():
    receipt = json.loads(Path("/scan/scan.json").read_text())
    scan_result = receipt.get("scan_result", {})
    if (set(receipt) != {"scan_result", "source_bytes_bounded"}
            or receipt["source_bytes_bounded"] is not True
            or set(scan_result) != {"scanner", "status", "source_digest"}
            or scan_result.get("scanner") != SCAN_ID
            or scan_result.get("status") != "pass"
            or scan_result.get("source_digest") != digest(FIXTURE)):
        raise ValueError("scanner_receipt_invalid")
    return scan_result


def expected_lineage(model):
    return {"external_origin": "http://model-source:8080/model.json",
            "source_digest": digest(FIXTURE), "scan_result": scan(), "internalization_date": MEASURED_DATE,
            "date_kind": "fixture-date", "decision": "approved", "decision_ref": "fixture-approval-001",
            "subject_digest": digest(model)}


def validate(lineage, model):
    expected = expected_lineage(model)
    if set(lineage) != set(expected) or any(not value for value in lineage.values()):
        raise ValueError("metadata_incomplete")
    if lineage["decision"] != "approved":
        raise ValueError("decision_not_approved")
    if lineage["subject_digest"] != expected["subject_digest"] or lineage["source_digest"] != expected["source_digest"]:
        raise ValueError("digest_mismatch")
    if lineage["scan_result"] != expected["scan_result"] or lineage["scan_result"]["status"] != "pass":
        raise ValueError("scan_result_mismatch")
    if lineage["date_kind"] != "fixture-date" or date.fromisoformat(lineage["internalization_date"]).isoformat() != MEASURED_DATE:
        raise ValueError("invalid_internalization_date")
    if lineage["external_origin"] != expected["external_origin"] or lineage["decision_ref"] != expected["decision_ref"]:
        raise ValueError("unexpected_fixture_origin_or_decision")


def publish_lineage(subject_digest, model, lineage):
    payload = canonical(lineage)
    config = CONFIG
    upload_blob(config)
    upload_blob(payload)
    attachment = canonical({"schemaVersion": 2, "mediaType": OCI_MANIFEST,
                            "artifactType": LINEAGE_TYPE,
                            "config": descriptor(OCI_EMPTY, config),
                            "layers": [descriptor(LINEAGE_TYPE, payload)],
                            "subject": descriptor(OCI_MANIFEST, model)})
    attachment_digest = digest(attachment)
    put_manifest(attachment_digest, attachment)
    tag = subject_digest.replace(":", "-", 1)
    status, _, raw = fetch_manifest(tag)
    index = ({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": []}
             if status == 404 else json.loads(raw))
    descriptor_row = {**descriptor(OCI_MANIFEST, attachment), "artifactType": LINEAGE_TYPE}
    if not any(row.get("digest") == attachment_digest for row in index["manifests"]):
        index["manifests"].append(descriptor_row)
    put_manifest(tag, canonical(index), OCI_INDEX)


def retrieve(model, expected_lineage):
    subject_digest = digest(model)
    tag = subject_digest.replace(":", "-", 1)
    status, _, raw = fetch_manifest(tag)
    if status != 200:
        raise RuntimeError("referrers tag missing")
    entries = [item for item in json.loads(raw)["manifests"]
               if item.get("artifactType") == LINEAGE_TYPE]
    if len(entries) != 1:
        raise RuntimeError("expected one lineage referrer")
    item = entries[0]
    status, _, attachment = fetch_manifest(item["digest"])
    if status != 200 or digest(attachment) != item["digest"] or len(attachment) != item["size"]:
        raise RuntimeError("lineage manifest digest or size mismatch")
    manifest = json.loads(attachment)
    if manifest.get("subject") != descriptor(OCI_MANIFEST, model):
        raise RuntimeError("lineage artifact subject mismatch")
    blob = manifest["layers"][0]
    status, _, payload = request("GET", "/blobs/" + quote(blob["digest"], safe=":"))
    if status != 200 or digest(payload) != blob["digest"] or len(payload) != blob["size"]:
        raise RuntimeError("lineage blob digest mismatch")
    lineage = json.loads(payload)
    if lineage != expected_lineage or lineage["subject_digest"] != subject_digest:
        raise RuntimeError("lineage content is not bound to the expected subject")
    return digest(payload)


def enroll(tag, model, lineage):
    validate(lineage, model)
    upload_blob(CONFIG)
    upload_blob(FIXTURE)
    subject = digest(model)
    put_manifest(subject, model)
    publish_lineage(subject, model, lineage)
    if retrieve(model, lineage) != digest(canonical(lineage)):
        raise RuntimeError("approved lineage differs before eligible tag publication")
    put_manifest(tag, model)


def fetch_complete(model, lineage):
    status, _, raw = fetch_manifest("approved-model")
    if status != 200 or raw != model:
        raise RuntimeError("approved manifest is absent or changed")
    status, _, artifact = request("GET", "/blobs/" + digest(FIXTURE))
    if status != 200 or artifact != FIXTURE:
        raise RuntimeError("approved model content is absent or changed")
    lineage_sha = retrieve(raw, lineage)
    if lineage_sha != digest(canonical(lineage)):
        raise RuntimeError("approved lineage is absent or changed")
    return {"approved_model_retrievable": True, "approved_lineage_retrievable": True,
            "source_digest": digest(artifact), "subject_digest": digest(raw),
            "lineage_digest": lineage_sha}


def main(verify=False):
    config, model = model_manifest()
    lineage = expected_lineage(model)
    if verify:
        print(json.dumps(fetch_complete(model, lineage), sort_keys=True))
        return

    upload_blob(config)
    upload_blob(FIXTURE)
    red_status = put_manifest("unreviewed-model", model)
    _, _, baseline = fetch_manifest("unreviewed-model")
    if baseline != model:
        raise RuntimeError("baseline did not store the exact inert artifact")
    tag = digest(model).replace(":", "-", 1)
    missing_history = fetch_manifest(tag)[0] == 404

    rejected = {}
    for label, candidate in (
        ("missing", {"external_origin": lineage["external_origin"]}),
        ("unapproved", {**lineage, "decision": "pending"}),
        ("wrong-scan-result", {**lineage, "scan_result": {**scan(), "source_digest": "sha256:" + "0" * 64}}),
    ):
        try:
            enroll("rejected-" + label, model, candidate)
        except ValueError as error:
            rejected[label] = str(error)
        else:
            raise RuntimeError("an invalid record reached publication")
    absent = all(fetch_manifest("rejected-" + label)[0] == 404 for label in rejected)
    enroll("approved-model", model, lineage)
    loaded = fetch_complete(model, lineage)
    print(json.dumps({"red_registry_status": red_status, "red_has_no_lineage": missing_history,
                      "rejected": rejected, "rejected_enrollment_tags_absent": absent,
                      "lineage": lineage, **loaded}, sort_keys=True))


if __name__ == "__main__":
    import sys
    main(verify=sys.argv[1:] == ["verify"])
