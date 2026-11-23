"""Small OCI Distribution client; returns stable status and digest-match summaries only."""
import base64
import hashlib
import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"


def _digest(body):
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _request(base, username, method, path, body=None, content_type=None):
    password = Path("/auth/password").read_text().strip()
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    headers = {"Authorization": "Basic " + token, "Accept": MANIFEST_TYPE}
    if content_type:
        headers["Content-Type"] = content_type
    try:
        with urlopen(Request(base + path, data=body, headers=headers, method=method), timeout=8) as response:
            return response.status, dict(response.headers.items()), response.read()
    except HTTPError as response:
        return response.code, dict(response.headers.items()), response.read()
    except (URLError, TimeoutError, OSError):
        raise RuntimeError("registry endpoint unavailable") from None


def _manifest(label):
    config = b"{}"
    config_digest = _digest(config)
    body = json.dumps({
        "schemaVersion": 2,
        "mediaType": MANIFEST_TYPE,
        "artifactType": "application/vnd.saf.fixture.v1",
        "annotations": {"org.opencontainers.image.title": label},
        "config": {"mediaType": "application/vnd.oci.empty.v1+json",
                   "digest": config_digest, "size": len(config)},
        "layers": [],
    }, sort_keys=True, separators=(",", ":")).encode()
    return config, config_digest, body, _digest(body)


def _push_blob(base, username, repository, config, config_digest):
    start, headers, _ = _request(base, username, "POST",
                                 f"/v2/{repository}/blobs/uploads/", b"")
    if start != 202 or "Location" not in headers:
        raise RuntimeError("OCI blob upload start did not return 202 and Location")
    upload = urljoin(base, headers["Location"])
    upload += ("&" if "?" in upload else "?") + "digest=" + config_digest
    status, _, _ = _request_url(upload, username, "PUT", config,
                                "application/octet-stream")
    if status != 201:
        raise RuntimeError("OCI config blob upload did not return 201")


def _request_url(url, username, method, body, content_type):
    password = Path("/auth/password").read_text().strip()
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    headers = {"Authorization": "Basic " + token, "Content-Type": content_type,
               "Accept": MANIFEST_TYPE}
    try:
        with urlopen(Request(url, data=body, headers=headers, method=method), timeout=8) as response:
            return response.status, dict(response.headers.items()), response.read()
    except HTTPError as response:
        return response.code, dict(response.headers.items()), response.read()
    except (URLError, TimeoutError, OSError):
        raise RuntimeError("registry endpoint unavailable") from None


def _push(base, username, repository, tag, label):
    config, config_digest, manifest, manifest_digest = _manifest(label)
    _push_blob(base, username, repository, config, config_digest)
    status, _, _ = _request(base, username, "PUT",
                            f"/v2/{repository}/manifests/{tag}", manifest, MANIFEST_TYPE)
    return status, manifest_digest


def _get(base, username, repository, reference):
    status, headers, body = _request(base, username, "GET",
                                     f"/v2/{repository}/manifests/{reference}")
    if status != 200:
        return status, None, None
    digest = _digest(body)
    advertised = next((value for key, value in headers.items()
                       if key.lower() == "docker-content-digest"), None)
    if advertised and digest != advertised:
        raise RuntimeError("manifest digest header mismatch")
    return status, digest, body


def _seed(base, username, repository):
    status, digest = _push(base, username, repository, "stable", "seed-" + repository)
    if status != 201:
        raise RuntimeError("fixture seed manifest did not return 201")
    return {"ok": True, "create_status": status}


def _inference_scope(base, username):
    serving_status, serving_digest, _ = _get(base, username, "serving/model", "stable")
    training_status, _, _ = _get(base, username, "training/model", "stable")
    if serving_status != 200 or serving_digest is None:
        raise RuntimeError("approved serving repository was not readable")
    write_status, _, _ = _request(base, username, "PUT", "/v2/serving/model/manifests/inference-v1",
                               _manifest("inference-new")[2], MANIFEST_TYPE)
    return {"ok": True, "serving_status": serving_status,
            "serving_digest_matches": serving_digest == _manifest("seed-serving/model")[3],
            "training_status": training_status, "serving_write_status": write_status}


def _pull_training(base, username):
    status, digest, _ = _get(base, username, "training/model", "stable")
    if status == 200 and digest is None:
        raise RuntimeError("training manifest digest missing")
    return {"ok": True, "status": status}


def _publisher_cycle(base, username):
    create_status, _ = _push(base, username, "training/model", "published-v1", "publisher-new")
    update_status, updated_digest = _push(base, username, "training/model", "stable", "publisher-update")
    target = updated_digest if update_status == 201 else _manifest("seed-training/model")[3]
    delete_path = f"/v2/training/model/manifests/{target}"
    delete_status, _, _ = _request(base, username, "DELETE", delete_path)
    _, stable_digest, _ = _get(base, username, "training/model", "stable")
    return {"ok": True, "create_status": create_status,
            "update_status": update_status, "delete_status": delete_status, "delete_path": delete_path,
            "cross_repo_create_status": _cross_repo_publish(base, username),
            "stable_digest_preserved": stable_digest == _manifest("seed-training/model")[3]}


def _cross_repo_publish(base, username):
    # The target already contains the shared inert config from seeding.
    manifest = _manifest("cross-repository")[2]
    status, _, _ = _request(base, username, "PUT",
                            "/v2/serving/model/manifests/cross-repo", manifest, MANIFEST_TYPE)
    return status


def _steward_cycle(base, username):
    update_status, updated_digest = _push(base, username, "training/model", "stable", "steward-update")
    _, read_digest, _ = _get(base, username, "training/model", "stable")
    delete_path = f"/v2/training/model/manifests/{updated_digest}"
    delete_status, _, _ = _request(base, username, "DELETE", delete_path)
    absent, _, _ = _get(base, username, "training/model", updated_digest)
    return {"ok": True, "update_status": update_status, "delete_status": delete_status,
            "updated_digest_matches": read_digest == updated_digest,
            "post_delete_status": absent, "delete_path": delete_path}


def main():
    if len(sys.argv) != 4:
        raise RuntimeError("invalid probe invocation")
    base, scenario, username = sys.argv[1:]
    if scenario.startswith("seed:") and username == "seed":
        result = _seed(base, username, scenario.split(":", 1)[1])
    elif scenario == "inference-scope" and username == "inference":
        result = _inference_scope(base, username)
    elif scenario == "pull-training":
        result = _pull_training(base, username)
    elif scenario == "publisher-cycle" and username == "publisher":
        result = _publisher_cycle(base, username)
    elif scenario == "steward-cycle" and username == "steward":
        result = _steward_cycle(base, username)
    else:
        raise RuntimeError("invalid probe scenario")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Emit a fixed category only; never relay credentials or registry response bodies.
        print(json.dumps({"ok": False, "error": "OCI request failed"}))
        raise SystemExit(1)
