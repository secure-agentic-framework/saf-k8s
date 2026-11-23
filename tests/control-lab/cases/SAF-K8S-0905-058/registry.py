"""Case-owned OCI Distribution client for attaching and fetching DSSE payloads."""
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import Request, urlopen

BASE = "http://model-promotion-registry:5000"
REPO = f"{BASE}/v2/inert/models"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
INDEX = "application/vnd.oci.image.index.v1+json"
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


def manifest(artifact_type, raw, media):
    config = b"{}"
    put_blob(config)
    put_blob(raw)
    value = {"schemaVersion": 2, "mediaType": MANIFEST, "artifactType": artifact_type,
             "config": descriptor(EMPTY_TYPE, config), "layers": [descriptor(media, raw)]}
    return canonical(value)


def put_manifest(ref, raw, media=MANIFEST):
    status, _, _ = request("PUT", REPO + "/manifests/" + ref, raw, media)
    if status != 201:
        raise RuntimeError(f"manifest publication returned {status}")


def operate(phase):
    if phase == "seed":
        expected = Path("/app/model.json").read_bytes()
        raw = manifest("application/vnd.saf.fixture-model.v1+json", expected, "application/json")
        wanted = digest(raw)
        put_manifest(wanted, raw)
        reference = BASE.removeprefix("http://") + "/inert/models@" + wanted
        model_hash = digest(expected).split(":", 1)[1]
    else:
        reference, model_hash = os.environ["MODEL_REF"], os.environ["MODEL_DIGEST"]
        prefix, wanted = reference.split("@", 1)
        if prefix != BASE.removeprefix("http://") + "/inert/models":
            raise RuntimeError("unrecognized case-owned model registry")
    status, _, raw = request("GET", REPO + "/manifests/" + wanted)
    if status != 200 or digest(raw) != wanted:
        raise RuntimeError("model manifest readback differs")
    layer, = json.loads(raw)["layers"]
    status, _, artifact = request("GET", REPO + "/blobs/" + layer["digest"])
    if status != 200 or descriptor("application/json", artifact) != layer or digest(artifact) != "sha256:" + model_hash:
        raise RuntimeError("model contents do not satisfy the approval")
    return {"reference": reference, "model_sha256": model_hash}


if __name__ == "__main__":
    print(json.dumps(operate(sys.argv[1]), sort_keys=True))
