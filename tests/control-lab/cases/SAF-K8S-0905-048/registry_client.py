"""Seed and retrieve only the fixture artifacts in the disposable registry."""
from hashlib import sha256
import json
import sys
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

ORIGIN = "http://saf-048-registry:5000"
REPO = "/v2/saf-fixture/model"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MODEL = "application/vnd.saf.model-fixture.v1+json"


def request(path, expected, method="GET", payload=None, kind=None):
    headers = {"Accept": MANIFEST}
    if kind is not None:
        headers["Content-Type"] = kind
    msg = Request(ORIGIN + path, data=payload, headers=headers, method=method)
    with urlopen(msg, timeout=10) as response:
        if response.status != expected:
            raise RuntimeError("fixture registry returned an unexpected status")
        return response.headers, response.read(65536)


def digest(raw):
    return "sha256:" + sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def upload(raw, media_type):
    headers, _ = request(REPO + "/blobs/uploads/", 202, "POST", b"")
    location = urlsplit(headers["Location"])
    query = location.query + "&" if location.query else ""
    blob = digest(raw)
    request(location.path + "?" + query + "digest=" + quote(blob, safe=":"), 201,
            "PUT", raw, "application/octet-stream")
    return {"digest": blob, "size": len(raw), "mediaType": media_type}


def fetch(reference):
    meta, raw = request(REPO + "/manifests/" + quote(reference, safe=":"), 200)
    actual = digest(raw)
    if meta.get("Docker-Content-Digest") != actual:
        raise RuntimeError("registry digest did not match retrieved manifest bytes")
    manifest = json.loads(raw)
    desc, = manifest["layers"]
    _, payload = request(REPO + "/blobs/" + desc["digest"], 200)
    if digest(payload) != desc["digest"] or len(payload) != desc["size"]:
        raise RuntimeError("registry returned an unexpected model payload")
    return {"manifest_digest": actual, "payload_digest": desc["digest"],
            "fixture_version": json.loads(payload)["fixture_version"]}


def put(version, tag):
    payload = canonical({"fixture_version": version, "fixture": "public inert model marker"})
    contents = canonical({"schemaVersion": 2, "mediaType": MANIFEST, "artifactType": MODEL,
                          "config": upload(b"{}", "application/vnd.oci.empty.v1+json"),
                          "layers": [upload(payload, MODEL)]})
    meta, _ = request(REPO + "/manifests/" + tag, 201, "PUT", contents, MANIFEST)
    if meta.get("Docker-Content-Digest") != digest(contents):
        raise RuntimeError("stored manifest does not match submitted model artifact")
    observed = fetch(tag)
    if observed["manifest_digest"] != digest(contents) or observed["fixture_version"] != version:
        raise RuntimeError("retrieved manifest does not resolve to the submitted fixture version")
    return observed


if sys.argv[1:] == ["seed"]:
    result = put("reviewed-v1", "reviewed")
elif sys.argv[1:] == ["advance"]:
    result = put("replacement-v2", "reviewed")
elif len(sys.argv) == 3 and sys.argv[1] == "read" and sys.argv[2].startswith("sha256:"):
    result = fetch(sys.argv[2])
else:
    raise SystemExit("invalid fixture operation")
print(json.dumps(result, sort_keys=True))
