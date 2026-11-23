"""Case-owned OCI Distribution client for attaching and fetching DSSE payloads."""
import hashlib
import json
from pathlib import Path
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import Request, urlopen

BASE = "http://attestation-registry:5000"
REPO = f"{BASE}/v2/inert/models"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
INDEX = "application/vnd.oci.image.index.v1+json"
DSSE = "application/vnd.dsse.envelope.v1+json"
EMPTY_TYPE = "application/vnd.oci.empty.v1+json"


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def descriptor(media, raw):
    return {"mediaType": media, "digest": digest(raw), "size": len(raw)}


def canonical(row):
    return json.dumps(row, sort_keys=True, separators=(",", ":")).encode()


def request(method, url, body=None, media=None):
    if urlsplit(url).netloc != urlsplit(BASE).netloc:
        raise RuntimeError("unexpected non-fixture upload URL")
    headers = {"Accept": f"{MANIFEST}, {INDEX}"}
    if media:
        headers["Content-Type"] = media
    try:
        with urlopen(Request(url, data=body, headers=headers, method=method), timeout=8) as result:
            return result.status, result.headers, result.read()
    except HTTPError as error:
        return error.code, error.headers, error.read()


def put_blob(raw):
    status, headers, _ = request("POST", REPO + "/blobs/uploads/", b"")
    if status != 202 or "Location" not in headers:
        raise RuntimeError("blob upload initialization failed")
    upload = urljoin(BASE, headers["Location"])
    query = urlencode({"digest": digest(raw)})
    status, _, _ = request("PUT", upload + ("&" if "?" in upload else "?") + query, raw, "application/octet-stream")
    if status != 201:
        raise RuntimeError("blob upload failed")


def manifest(artifact_type, raw, media, *, subject=None):
    config = b"{}"
    put_blob(config)
    put_blob(raw)
    value = {"schemaVersion": 2, "mediaType": MANIFEST, "artifactType": artifact_type,
             "config": descriptor(EMPTY_TYPE, config), "layers": [descriptor(media, raw)]}
    if subject is not None:
        value["subject"] = subject
    return canonical(value)


def put_manifest(ref, raw, media=MANIFEST):
    status, _, _ = request("PUT", REPO + "/manifests/" + ref, raw, media)
    if status != 201:
        raise RuntimeError(f"manifest publication returned {status}")


def expect_raw(url, wanted):
    status, _, actual = request("GET", url)
    if status != 200 or actual != wanted:
        raise RuntimeError(f"fixture readback returned {status} or different bytes")
    return actual


def operate(phase):
    package = Path("/artifacts/model-package.json").read_bytes()
    if phase == "off":
        model = manifest("application/vnd.saf.model-package.v1", package, "application/json")
        put_manifest("model-v1", model)
    else:
        status, _, model = request("GET", REPO + "/manifests/model-v1")
        if status != 200:
            raise RuntimeError("published package manifest is absent")
    subject = descriptor(MANIFEST, model)
    ref_tag = subject["digest"].replace(":", "-", 1)
    manifest_url = REPO + "/manifests/"
    expect_raw(REPO + "/blobs/" + digest(package), package)
    if json.loads(model)["layers"] != [descriptor("application/json", package)]:
        raise RuntimeError("subject does not refer to package bytes")
    if phase == "off":
        status, _, _ = request("GET", manifest_url + ref_tag)
        return {"subject": subject["digest"], "referrers_status": status}

    references = {}
    for step in ("training", "packaging"):
        envelope = Path("/artifacts", step + ".envelope").read_bytes()
        attachment = manifest(DSSE, envelope, DSSE, subject=subject)
        item = dict(descriptor(MANIFEST, attachment), artifactType=DSSE,
                    annotations={"org.opencontainers.image.title": step})
        put_manifest(item["digest"], attachment)
        references[step] = (item, attachment, envelope)
    index = canonical({"schemaVersion": 2, "mediaType": INDEX,
                       "manifests": [item for item, _, _ in references.values()]})
    put_manifest(ref_tag, index, INDEX)
    found = json.loads(expect_raw(manifest_url + ref_tag, index))["manifests"]
    fetched = {}
    for item in found:
        step = item["annotations"]["org.opencontainers.image.title"]
        wanted_item, attachment, envelope = references[step]
        stored = json.loads(expect_raw(manifest_url + item["digest"], attachment))
        if item != wanted_item or stored["subject"] != subject or stored["layers"] != [descriptor(DSSE, envelope)]:
            raise RuntimeError("attestation subject or descriptor differs")
        layer = expect_raw(REPO + "/blobs/" + stored["layers"][0]["digest"], envelope)
        fetched[step] = digest(layer)
    return {"subject": subject["digest"], "attestations": fetched}


if __name__ == "__main__":
    print(json.dumps(operate(sys.argv[1]), sort_keys=True))
