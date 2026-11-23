"""Publish, read, retag and delete an inert manifest in the case-owned registry."""
import base64
import hashlib
import json
from pathlib import Path
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen

REPO = "saf-test/audit-model"
MEDIA = "application/vnd.oci.image.manifest.v1+json"


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _request(url, method, body=None, media=None):
    secret = Path("/auth/password").read_text().strip()
    identity = base64.b64encode(f"fixture-publisher:{secret}".encode()).decode()
    headers = {"Authorization": "Basic " + identity, "Accept": MEDIA}
    if media:
        headers["Content-Type"] = media
    try:
        with urlopen(Request(url, data=body, headers=headers, method=method), timeout=8) as response:
            return response.status, response.headers, response.read()
    except HTTPError as error:
        return error.code, error.headers, error.read()


def main(base, tag):
    root = f"{base}/v2/{REPO}"
    config = b"{}"
    config_digest = _digest(config)
    status, headers, _ = _request(f"{root}/blobs/uploads/", "POST", b"")
    if status != 202:
        raise RuntimeError(f"blob upload initialization returned {status}")
    location = urljoin(base, headers["Location"])
    url = location + ("&" if "?" in location else "?") + urlencode({"digest": config_digest})
    status, _, _ = _request(url, "PUT", config, "application/octet-stream")
    if status != 201:
        raise RuntimeError(f"blob upload returned {status}")
    manifest = json.dumps({
        "schemaVersion": 2, "mediaType": MEDIA, "artifactType": "application/vnd.saf.fixture.v1",
        "annotations": {"org.opencontainers.image.title": f"inert-model-{tag}"},
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": config_digest, "size": len(config)},
        "layers": [],
    }, sort_keys=True, separators=(",", ":")).encode()
    digest = _digest(manifest)
    manifests = f"{root}/manifests"
    publish = _request(f"{manifests}/{tag}-v1", "PUT", manifest, MEDIA)[0]
    pull, _, fetched = _request(f"{manifests}/{tag}-v1", "GET")
    retag = _request(f"{manifests}/{tag}-v2", "PUT", manifest, MEDIA)[0]
    deleted = _request(f"{manifests}/{digest}", "DELETE")[0]
    print(json.dumps({"publish_status": publish, "pull_status": pull, "retag_status": retag,
                      "delete_status": deleted, "digest": digest,
                      "pull_digest": _digest(fetched) if pull == 200 else None}))


if __name__ == "__main__":
    main(*sys.argv[1:])
