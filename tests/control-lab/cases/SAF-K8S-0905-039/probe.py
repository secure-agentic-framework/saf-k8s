"""OCI read probe for the isolated entitlement-review case; emits status and digest only."""
import hashlib
import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen


def main():
    if len(sys.argv) != 4:
        raise RuntimeError("invalid fixture invocation")
    base, identity, expected_digest = sys.argv[1:]
    password = Path(f"/auth/{identity}/password").read_text().strip()
    # Construct the Basic header in memory and never include it in output.
    from base64 import b64encode
    authorization = "Basic " + b64encode(f"{identity}:{password}".encode()).decode()
    headers = {"Authorization": authorization,
               "Accept": "application/vnd.oci.image.manifest.v1+json"}

    def request(method, path, body=None, content_type=None):
        request_headers = dict(headers)
        if content_type:
            request_headers["Content-Type"] = content_type
        req = Request(base + path, data=body, headers=request_headers, method=method)
        try:
            with urlopen(req, timeout=8) as response:
                return response.status, dict(response.headers.items()), response.read()
        except HTTPError as response:
            return response.code, dict(response.headers.items()), response.read()

    if identity == "seed" and expected_digest == "seed":
        status, digest = seed(request, base, headers)
        print(json.dumps({"ok": True, "status": status, "digest": digest}, sort_keys=True))
        return

    try:
        status, _, body = request("GET", "/v2/team/model/manifests/stable")
    except (URLError, TimeoutError, OSError):
        print(json.dumps({"ok": False, "error": "registry unavailable"}, sort_keys=True))
        raise SystemExit(2)

    digest = "sha256:" + hashlib.sha256(body).hexdigest() if status == 200 else None
    observation = {
        "ok": True,
        "method": "GET",
        "path": "/v2/team/model/manifests/stable",
        "identity": identity,
        "status": status,
        "digest_matches_expected": digest == expected_digest if status == 200 else None,
    }
    print(json.dumps(observation, sort_keys=True))


FIXTURE_CONFIG = b"{}"
FIXTURE_MODEL = b'{"algorithm":"fixture-linear","bias":1.0,"weight":2.0}'
def seed(request, base, headers):
    """Write only the fixture's inert artifact, then return its stable digest."""
    config_digest = "sha256:" + hashlib.sha256(FIXTURE_CONFIG).hexdigest()
    model_digest = "sha256:" + hashlib.sha256(FIXTURE_MODEL).hexdigest()
    for content, digest in ((FIXTURE_CONFIG, config_digest), (FIXTURE_MODEL, model_digest)):
        status, response_headers, _ = request("POST", "/v2/team/model/blobs/uploads/", b"")
        if status != 202 or "Location" not in response_headers:
            raise RuntimeError("fixture blob upload did not start")
        upload_url = urljoin(base, response_headers["Location"])
        if (urlsplit(upload_url).scheme, urlsplit(upload_url).netloc) != (urlsplit(base).scheme, urlsplit(base).netloc):
            raise RuntimeError("fixture registry returned an unexpected upload origin")
        upload_url += ("&" if "?" in upload_url else "?") + "digest=" + digest
        upload_req = Request(upload_url, data=content,
                             headers={**headers, "Content-Type": "application/octet-stream"}, method="PUT")
        try:
            with urlopen(upload_req, timeout=8) as response:
                upload_status = response.status
        except HTTPError as response:
            upload_status = response.code
        if upload_status != 201:
            raise RuntimeError("fixture blob upload did not complete")

    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.saf.fixture.v1",
        "annotations": {"org.opencontainers.image.title": "seed-team-model"},
        "config": {"mediaType": "application/vnd.oci.empty.v1+json",
                    "digest": config_digest, "size": len(FIXTURE_CONFIG)},
        "layers": [{"mediaType": "application/vnd.saf.fixture.model.v1+json",
                    "digest": model_digest, "size": len(FIXTURE_MODEL)}],
    }, sort_keys=True, separators=(",", ":")).encode()
    status, _, _ = request("PUT", "/v2/team/model/manifests/stable", manifest,
                           "application/vnd.oci.image.manifest.v1+json")
    return status, "sha256:" + hashlib.sha256(manifest).hexdigest()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Suppress exception text so credentials or registry response data cannot escape.
        print(json.dumps({"ok": False, "error": "probe failed"}, sort_keys=True))
        raise SystemExit(2)
