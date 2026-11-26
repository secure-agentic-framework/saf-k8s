"""Create and pull one empty, inert OCI artifact from the local Zot fixture."""
import base64
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import urljoin
from urllib.request import Request, urlopen

BASE = sys.argv[1]
REPO = "saf-test/model-a"
TAG = "alert-marker-v1"
MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def request(method, url, body=None, content_type=None):
    credential = "fixture-publisher:" + Path("/auth/password").read_text().strip()
    authorization = base64.b64encode(credential.encode()).decode()
    headers = {"Accept": MANIFEST_TYPE, "Authorization": "Basic " + authorization}
    if content_type:
        headers["Content-Type"] = content_type
    req = Request(url, data=body, headers=headers, method=method)
    with urlopen(req, timeout=8) as response:
        return response.status, dict(response.headers.items()), response.read()


config = b"{}"
config_digest = digest(config)
status, headers, _ = request("POST", f"{BASE}/v2/{REPO}/blobs/uploads/", b"")
if status != 202 or "Location" not in headers:
    raise SystemExit("local Zot fixture rejected bounded blob start")
upload = urljoin(BASE, headers["Location"])
upload += ("&" if "?" in upload else "?") + "digest=" + config_digest
status, _, _ = request("PUT", upload, config, "application/octet-stream")
if status != 201:
    raise SystemExit("local Zot fixture rejected empty config blob")

manifest = json.dumps({
    "schemaVersion": 2,
    "mediaType": MANIFEST_TYPE,
    "artifactType": "application/vnd.saf.fixture.v1",
    "annotations": {"org.opencontainers.image.title": "saf-empty-alert-marker"},
    "config": {"mediaType": "application/vnd.oci.empty.v1+json",
               "digest": config_digest, "size": len(config)},
    "layers": [],
}, sort_keys=True, separators=(",", ":")).encode()
manifest_digest = digest(manifest)
status, _, _ = request("PUT", f"{BASE}/v2/{REPO}/manifests/{TAG}", manifest, MANIFEST_TYPE)
if status != 201:
    raise SystemExit("local Zot fixture rejected inert manifest create")
status, _, body = request("GET", f"{BASE}/v2/{REPO}/manifests/{TAG}")
if status != 200 or digest(body) != manifest_digest:
    raise SystemExit("local Zot fixture marker readback mismatch")
print(json.dumps({"create_status": 201, "pull_status": 200,
                  "manifest_digest_matches": True, "payload_kind": "empty-config-no-layers"},
                 sort_keys=True))
