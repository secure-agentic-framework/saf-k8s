"""Small OCI Distribution API client; emits status/digest summaries only."""
import base64
import hashlib
import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


REPOSITORY = "saf-test/model"
TAG = "reviewed-v1"
SECOND_TAG = "approved-v2"
MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def request(method, url, body=None, content_type=None):
    userpass = "fixture-publisher:" + Path("/auth/password").read_text().strip()
    auth = base64.b64encode(userpass.encode()).decode()
    headers = {"Accept": MANIFEST_TYPE, "Authorization": "Basic " + auth}
    if content_type:
        headers["Content-Type"] = content_type
    req = Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(req, timeout=8) as response:
            return response.status, dict(response.headers.items()), response.read()
    except HTTPError as response:
        return response.code, dict(response.headers.items()), response.read()
    except (URLError, TimeoutError, OSError):
        raise RuntimeError("registry API request failed") from None


def create_artifact(base, label):
    # OCI empty config plus a fixed artifactType and title annotation keeps the two
    # manifest digests distinct without carrying executable or model payload bytes.
    config = b"{}"
    config_digest = digest(config)
    status, headers, _ = request("POST", f"{base}/v2/{REPOSITORY}/blobs/uploads/", b"")
    if status != 202 or "Location" not in headers:
        raise RuntimeError("registry rejected OCI blob upload start")
    upload_url = urljoin(base, headers["Location"])
    if "?" in upload_url:
        upload_url += "&"
    else:
        upload_url += "?"
    status, _, _ = request("PUT", upload_url + "digest=" + config_digest, config,
                          "application/octet-stream")
    if status != 201:
        raise RuntimeError("registry rejected OCI config blob")

    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": MANIFEST_TYPE,
        "artifactType": "application/vnd.saf.fixture.v1",
        "annotations": {"org.opencontainers.image.title": label},
        "config": {"mediaType": "application/vnd.oci.empty.v1+json",
                   "digest": config_digest, "size": len(config)},
        "layers": [],
    }, sort_keys=True, separators=(",", ":")).encode()
    return manifest, digest(manifest)


def push(base, tag, artifact):
    manifest, manifest_digest = artifact
    status, _, _ = request("PUT", f"{base}/v2/{REPOSITORY}/manifests/{tag}", manifest,
                          MANIFEST_TYPE)
    return status, manifest_digest


def read_digest(base, reference):
    status, headers, body = request("GET", f"{base}/v2/{REPOSITORY}/manifests/{reference}")
    if status != 200:
        return status, None
    found = digest(body)
    advertised = next((value for name,value in headers.items() if name.lower()=="docker-content-digest"), None)
    if advertised is not None and found != advertised:
        raise RuntimeError("registry digest header did not match manifest bytes")
    return status, found


def assert_status(actual, expected, label):
    if actual != expected:
        raise RuntimeError(label + " returned unexpected HTTP status")


def open_case(base):
    artifact_a = create_artifact(base, "fixture-a")
    artifact_b = create_artifact(base, "fixture-b")
    initial_status, initial_digest = push(base, TAG, artifact_a)
    assert_status(initial_status, 201, "initial create")
    status, found = read_digest(base, TAG)
    assert_status(status, 200, "initial digest read")
    if found != artifact_a[1]:
        raise RuntimeError("initial read digest did not match fixture A")

    overwrite_status, _ = push(base, TAG, artifact_b)
    status, overwritten_digest = read_digest(base, TAG)
    assert_status(status, 200, "post-overwrite digest read")
    if overwrite_status != 201 or overwritten_digest != artifact_b[1]:
        raise RuntimeError("open policy did not demonstrate tag overwrite")

    delete_status, _, _ = request(
        "DELETE", f"{base}/v2/{REPOSITORY}/manifests/{overwritten_digest}")
    if delete_status not in (200, 202):
        raise RuntimeError("open policy did not allow manifest deletion")
    missing_status, _ = read_digest(base, TAG)
    assert_status(missing_status, 404, "read after deletion")
    recreate_status, _ = push(base, TAG, artifact_a)
    status, recreated_digest = read_digest(base, TAG)
    assert_status(status, 200, "recreated digest read")
    if recreate_status != 201 or recreated_digest != artifact_a[1]:
        raise RuntimeError("open policy did not demonstrate delete/recreation")
    return {
        "ok": True, "initial_status": initial_status,
        "artifact_a_digest": artifact_a[1], "artifact_b_digest": artifact_b[1],
        "overwrite_status": overwrite_status, "overwrite_digest": overwritten_digest,
        "delete_status": delete_status, "recreate_status": recreate_status,
        "recreated_digest": recreated_digest,
    }


def locked_case(base):
    artifact_a = create_artifact(base, "fixture-a")
    artifact_b = create_artifact(base, "fixture-b")
    initial_status, _ = push(base, TAG, artifact_a)
    assert_status(initial_status, 201, "initial create")
    status, found = read_digest(base, TAG)
    assert_status(status, 200, "initial digest read")
    if found != artifact_a[1]:
        raise RuntimeError("initial read digest did not match fixture A")

    overwrite_status, _ = push(base, TAG, artifact_b)
    if overwrite_status != 403:
        raise RuntimeError(f"create-only policy returned {overwrite_status} for same-tag overwrite")
    status, after_overwrite = read_digest(base, TAG)
    assert_status(status, 200, "post-denial digest read")
    if after_overwrite != artifact_a[1]:
        raise RuntimeError("tag digest changed after denied overwrite")

    delete_status, _, _ = request(
        "DELETE", f"{base}/v2/{REPOSITORY}/manifests/{artifact_a[1]}")
    if delete_status != 403:
        raise RuntimeError(f"create-only policy returned {delete_status} for manifest deletion")
    status, after_delete = read_digest(base, TAG)
    assert_status(status, 200, "post-denial deletion read")
    if after_delete != artifact_a[1]:
        raise RuntimeError("tag digest changed after denied delete")

    positive_status, _ = push(base, SECOND_TAG, artifact_b)
    assert_status(positive_status, 201, "positive distinct-tag create")
    status, positive_digest = read_digest(base, SECOND_TAG)
    assert_status(status, 200, "positive digest read")
    if positive_digest != artifact_b[1]:
        raise RuntimeError("positive tag digest did not match fixture B")
    return {
        "ok": True, "initial_status": initial_status,
        "artifact_a_digest": artifact_a[1], "artifact_b_digest": artifact_b[1],
        "overwrite_status": overwrite_status, "after_overwrite_digest": after_overwrite,
        "delete_status": delete_status, "after_delete_digest": after_delete,
        "positive_create_status": positive_status, "positive_digest": positive_digest,
    }


def main():
    if len(sys.argv) != 3 or sys.argv[2] not in ("open", "locked"):
        raise RuntimeError("invalid probe invocation")
    result = (open_case(sys.argv[1]) if sys.argv[2] == "open"
              else locked_case(sys.argv[1]))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Emit only a stable category; never relay arbitrary registry response bodies.
        print(json.dumps({"ok": False, "error": str(error)}))
        raise SystemExit(1)
