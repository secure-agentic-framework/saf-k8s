"""Fixed-endpoint Distribution client, exact-pair gate, and ConfigMap reconciler."""
from hashlib import sha256
from http.client import HTTPConnection, HTTPSConnection
import gzip
import io
import ipaddress
import json
import os
from pathlib import PurePosixPath
import ssl
import sys
import tarfile
import time
from urllib.parse import urlsplit

NS = "saf-test"
SOURCE_NAME = "fixture-federation-source"
APPROVED_NAME = "fixture-federation-approved"
UNAPPROVED_NAME = "fixture-federation-unapproved"
REPOSITORY = "fixtures/saf-federation"
TAG = "fixture-v1"
MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"
def _fixture_layer():
    content = b"SAF harmless cross-cluster registry fixture v1\n"
    raw = io.BytesIO()
    info = tarfile.TarInfo("fixture.txt")
    info.size = len(content)
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(info, io.BytesIO(content))
    uncompressed = raw.getvalue()
    return uncompressed, gzip.compress(uncompressed, mtime=0)


UNCOMPRESSED_LAYER, LAYER = _fixture_layer()
LAYER_DIFF_ID = "sha256:" + sha256(UNCOMPRESSED_LAYER).hexdigest()
LAYER_DIGEST = "sha256:" + sha256(LAYER).hexdigest()
CONFIG = json.dumps({"architecture": "amd64", "os": "linux",
                     "rootfs": {"type": "layers", "diff_ids": [LAYER_DIFF_ID]},
                     "config": {}}, sort_keys=True, separators=(",", ":")).encode()
CONFIG_DIGEST = "sha256:" + sha256(CONFIG).hexdigest()
MANIFEST = json.dumps({
    "schemaVersion": 2,
    "mediaType": MEDIA_TYPE,
    "config": {"mediaType": "application/vnd.docker.container.image.v1+json",
               "size": len(CONFIG), "digest": CONFIG_DIGEST},
    "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(LAYER), "digest": LAYER_DIGEST}],
}, sort_keys=True, separators=(",", ":")).encode()
MANIFEST_DIGEST = "sha256:" + sha256(MANIFEST).hexdigest()
CONFIGMAP = "/api/v1/namespaces/saf-test/configmaps/fixture-federation-membership"
APPROVAL = "/api/v1/namespaces/saf-test/configmaps/fixture-approved-membership"
APPROVAL_NEXT = "/api/v1/namespaces/saf-test/configmaps/fixture-approved-membership-v2"
APPROVAL_POINTER = "/api/v1/namespaces/saf-test/configmaps/fixture-approved-membership-current"


def endpoint_map(peer_ip=None, approved_port=None, unapproved_port=None):
    ip = peer_ip if peer_ip is not None else os.environ.get("PEER_IP", "")
    parsed = ipaddress.ip_address(ip)
    if parsed.version != 4 or parsed.is_global or parsed.is_loopback or parsed.is_link_local:
        raise ValueError("Peer endpoint is not a private bridge address")
    host = str(parsed)
    first = approved_port if approved_port is not None else int(os.environ["APPROVED_PORT"])
    second = unapproved_port if unapproved_port is not None else int(os.environ["UNAPPROVED_PORT"])
    if first == second or any(not 30000 <= value <= 32767 for value in (first, second)):
        raise ValueError("Expected distinct Kind NodePort assignments")
    return {
        "source": f"http://{SOURCE_NAME}.{NS}.svc:5000",
        "destination_approved": f"http://{host}:{first}",
        "destination_unapproved": f"http://{host}:{second}",
    }


def labels_for_membership(document, endpoints):
    reverse = {url: label for label, url in endpoints.items()}
    return {"approval_revision": document.get("approval_name"),
            **{key: sorted(reverse[value] for value in document.get(key, []) if value in reverse)
               for key in ("approved", "active")}}


def _endpoint(url, endpoints):
    if url not in endpoints.values():
        raise ValueError("Network destination is not a case-owned registry")
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Invalid fixture registry endpoint")
    if parsed.path:
        raise ValueError("Registry base endpoint must not contain a path")
    return parsed


def registry_request(url, method, path, endpoints, body=None, headers=None):
    parsed = _endpoint(url, endpoints)
    if not path.startswith("/v2/") or ".." in PurePosixPath(path).parts:
        raise ValueError("Registry path is outside the fixed Distribution API")
    connection = HTTPConnection(parsed.hostname, parsed.port, timeout=8)
    try:
        request_headers = {"Host": parsed.netloc, **(headers or {})}
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        contents = response.read(2 * 1024 * 1024 + 1)
        if len(contents) > 2 * 1024 * 1024:
            raise ValueError("Registry body exceeds the fixture byte limit")
        return response.status, contents, dict(response.getheaders())
    finally:
        connection.close()


def _digest(data):
    return "sha256:" + sha256(data).hexdigest()


def _push_blob(url, blob_digest, blob, endpoints):
    status, _, headers = registry_request(url, "POST", f"/v2/{REPOSITORY}/blobs/uploads/",
                                         endpoints, headers={"Content-Length": "0"})
    if status != 202:
        raise RuntimeError("Distribution registry did not start the fixed blob upload")
    location = headers.get("Location") or headers.get("location")
    if not location:
        raise RuntimeError("Distribution registry omitted the blob upload location")
    base = _endpoint(url, endpoints)
    target = urlsplit(location)
    if (target.scheme not in ("", "http") or target.netloc not in ("", base.netloc)
            or target.username or target.password or target.fragment):
        raise RuntimeError("Registry upload location escaped its fixed endpoint")
    upload_path = target.path
    prefix = f"/v2/{REPOSITORY}/blobs/uploads/"
    if not upload_path.startswith(prefix) or "/../" in upload_path or not upload_path[len(prefix):]:
        raise RuntimeError("Registry upload location escaped its fixed repository")
    path = upload_path + "?" + target.query + ("&" if target.query else "") + "digest=" + blob_digest
    status, _, result_headers = registry_request(url, "PUT", path, endpoints, body=blob,
                                                 headers={"Content-Type": "application/octet-stream"})
    returned = result_headers.get("Docker-Content-Digest") or result_headers.get("docker-content-digest")
    if status != 201 or returned != blob_digest:
        raise RuntimeError("Distribution registry did not confirm the expected blob digest")


def _manifest(url, reference, endpoints):
    status, body, headers = registry_request(
        url, "GET", f"/v2/{REPOSITORY}/manifests/{reference}", endpoints,
        headers={"Accept": MEDIA_TYPE})
    if status == 404:
        return {"digest": None, "status": 404}
    if status != 200:
        raise RuntimeError("Distribution registry manifest read failed")
    actual = _digest(body)
    advertised = headers.get("Docker-Content-Digest") or headers.get("docker-content-digest")
    if actual != advertised:
        raise RuntimeError("Registry manifest digest header differs from locally calculated digest")
    return {"digest": actual, "status": 200, "body": body}


def _copy(source, destination, endpoints):
    source_manifest = _manifest(source, TAG, endpoints)
    if source_manifest.get("digest") != MANIFEST_DIGEST or source_manifest["body"] != MANIFEST:
        raise RuntimeError("Source registry does not contain the locked harmless manifest")
    for digest, expected in ((CONFIG_DIGEST, CONFIG), (LAYER_DIGEST, LAYER)):
        status, blob, _ = registry_request(source, "GET", f"/v2/{REPOSITORY}/blobs/{digest}", endpoints)
        if status != 200 or blob != expected or _digest(blob) != digest:
            raise RuntimeError("Source registry blob differs from the deterministic fixture")
        _push_blob(destination, digest, blob, endpoints)
    status, _, headers = registry_request(
        destination, "PUT", f"/v2/{REPOSITORY}/manifests/{TAG}", endpoints, body=MANIFEST,
        headers={"Content-Type": MEDIA_TYPE, "Content-Length": str(len(MANIFEST))})
    returned = headers.get("Docker-Content-Digest") or headers.get("docker-content-digest")
    if status != 201 or returned != MANIFEST_DIGEST:
        raise RuntimeError("Destination registry did not confirm the expected manifest digest")
    return {"decision": "baseline-written", "digest": MANIFEST_DIGEST}


def _registry_state(url, endpoints):
    state = _manifest(url, TAG, endpoints)
    if state["status"] == 200:
        for digest, expected in ((CONFIG_DIGEST, CONFIG), (LAYER_DIGEST, LAYER)):
            status, body, _ = registry_request(url, "GET", f"/v2/{REPOSITORY}/blobs/{digest}", endpoints)
            if status != 200 or body != expected or _digest(body) != digest:
                raise RuntimeError("Independent readback did not recover the expected image blob")
    return {"digest": state["digest"], "status": state["status"]}


def _registry_empty(url, endpoints):
    refs = (f"manifests/{TAG}", f"manifests/{MANIFEST_DIGEST}",
            f"blobs/{CONFIG_DIGEST}", f"blobs/{LAYER_DIGEST}")
    return {"all_fixture_content_absent": all(
        registry_request(url, "GET", f"/v2/{REPOSITORY}/{ref}", endpoints)[0] == 404 for ref in refs
    )}


def _api_request(method, path, body=None):
    token = open("/var/run/secrets/kubernetes.io/serviceaccount/token", "r").read().strip()
    context = ssl.create_default_context(cafile="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    connection = HTTPSConnection("kubernetes.default.svc", 443, context=context, timeout=8)
    try:
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode() if body is not None else None
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        if raw is not None:
            headers["Content-Type"] = "application/merge-patch+json"
        connection.request(method, path, body=raw, headers=headers)
        response = connection.getresponse()
        content = response.read()
        return response.status, json.loads(content) if content else None
    finally:
        connection.close()


def _membership():
    pointer_status, pointer = _api_request("GET", APPROVAL_POINTER)
    active_status, active = _api_request("GET", CONFIGMAP)
    if pointer_status != 200 or active_status != 200:
        raise RuntimeError("Could not read the approval revision pointer and active membership")
    approval_name = json.loads(pointer["data"]["current.json"])
    if approval_name not in {"fixture-approved-membership", "fixture-approved-membership-v2"}:
        raise RuntimeError("Current approval revision is outside the fixed fixture set")
    approval_path = APPROVAL if approval_name == "fixture-approved-membership" else APPROVAL_NEXT
    approved_status, approved = _api_request("GET", approval_path)
    if approved_status != 200 or active_status != 200 or approved.get("immutable") is not True:
        raise RuntimeError("Could not read the selected immutable approval snapshot")
    return {"approval_name": approval_name,
            "approved": json.loads(approved["data"]["approved.json"]),
            "active": json.loads(active["data"]["active.json"])}


def _approval_snapshot(name):
    if name not in {"fixture-approved-membership", "fixture-approved-membership-v2"}:
        raise RuntimeError("Approval snapshot is outside the fixed fixture set")
    path = APPROVAL if name == "fixture-approved-membership" else APPROVAL_NEXT
    status, snapshot = _api_request("GET", path)
    if status != 200 or snapshot.get("immutable") is not True:
        raise RuntimeError("Could not independently observe the immutable approval snapshot")
    return json.loads(snapshot["data"]["approved.json"])


def _patch_membership(value):
    status, _ = _api_request("PATCH", CONFIGMAP, {"data": {"active.json": json.dumps(value["active"])}})
    return status


def _replicate(destination, endpoints, governed):
    source = endpoints["source"]
    if governed:
        membership = _membership()
        approved = membership.get("approved", [])
        active = membership.get("active", [])
        if (source, destination) != (endpoints["source"], endpoints["destination_approved"]):
            return {"decision": "denied-endpoint-pair"}
        if source not in approved or destination not in approved or source not in active or destination not in active:
            return {"decision": "denied-endpoint-pair"}
    result = _copy(source, destination, endpoints)
    result["decision"] = "allowed" if governed else result["decision"]
    return result


def _call(operation):
    endpoints = endpoint_map()
    source = endpoints["source"]
    approved = endpoints["destination_approved"]
    unapproved = endpoints["destination_unapproved"]
    if operation == "wait-ready":
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                if all(registry_request(url, "GET", "/v2/", endpoints)[0] == 200
                       for url in endpoints.values()):
                    return {"ready": True}
            except (ConnectionRefusedError, TimeoutError):
                pass
            time.sleep(0.25)
        return {"ready": False}
    if operation == "manager-approval-write-denied":
        status, _ = _api_request("PATCH", APPROVAL, {"data": {"approved.json": json.dumps([source, unapproved])}})
        return {"http_status": status}
    if operation == "manager-revision-write-denied":
        status, _ = _api_request("PATCH", APPROVAL_POINTER,
                                 {"data": {"current.json": json.dumps("fixture-approved-membership-v2")}})
        return {"http_status": status}
    if operation == "advance-approval-revision":
        status, _ = _api_request("PATCH", APPROVAL_POINTER,
                                 {"data": {"current.json": json.dumps("fixture-approved-membership-v2")}})
        return {"http_status": status, "revision": "fixture-approved-membership-v2"}
    if operation == "seed":
        for digest, blob in ((CONFIG_DIGEST, CONFIG), (LAYER_DIGEST, LAYER)):
            _push_blob(source, digest, blob, endpoints)
        status, _, headers = registry_request(source, "PUT", f"/v2/{REPOSITORY}/manifests/{TAG}",
                                              endpoints, body=MANIFEST,
                                              headers={"Content-Type": MEDIA_TYPE,
                                                       "Content-Length": str(len(MANIFEST))})
        returned = headers.get("Docker-Content-Digest") or headers.get("docker-content-digest")
        if status != 201 or returned != MANIFEST_DIGEST:
            raise RuntimeError("Could not seed the real source Distribution registry")
        return {"digest": MANIFEST_DIGEST}
    if operation == "baseline-copy":
        return _copy(source, unapproved, endpoints)
    if operation == "governed-copy-unapproved":
        return _replicate(unapproved, endpoints, governed=True)
    if operation == "governed-copy-approved":
        return _replicate(approved, endpoints, governed=True)
    if operation == "observe-source":
        return _registry_state(source, endpoints)
    if operation == "observe-approved":
        return _registry_state(approved, endpoints)
    if operation == "observe-approved-empty":
        return _registry_empty(approved, endpoints)
    if operation == "observe-unapproved":
        return _registry_state(unapproved, endpoints)
    if operation == "observe-unapproved-empty":
        return _registry_empty(unapproved, endpoints)
    if operation == "observe-membership":
        return labels_for_membership(_membership(), endpoints)
    if operation == "observe-approval-revisions":
        current = _membership()
        return {"current": labels_for_membership(current, endpoints),
                "v1": sorted({value: label for label, value in endpoints.items()}[url]
                             for url in _approval_snapshot("fixture-approved-membership")
                             if url in endpoints.values()),
                "v2": sorted({value: label for label, value in endpoints.items()}[url]
                             for url in _approval_snapshot("fixture-approved-membership-v2")
                             if url in endpoints.values())}
    if operation == "observer-write-denied":
        current = _membership()
        changed = dict(current)
        changed["active"] = list(current.get("active", [])) + [unapproved]
        status = _patch_membership(changed)
        if status != 403:
            raise RuntimeError("Read-only observer unexpectedly changed membership")
        return {"http_status": status}
    if operation == "inject-drift":
        current = _membership()
        active = list(current.get("active", []))
        if unapproved not in active:
            active.append(unapproved)
        updated = dict(current, active=active)
        if _patch_membership(updated) != 200:
            raise RuntimeError("Manager could not inject the case-owned membership drift")
        return {"injected": "destination_unapproved"}
    if operation == "reconcile":
        changed = False
        passes = 0
        for _ in range(4):
            passes += 1
            current = _membership()
            approved_members = set(current.get("approved", []))
            active = list(current.get("active", []))
            repaired = [value for value in active if value in approved_members]
            if repaired == active:
                break
            updated = dict(current, active=repaired)
            if _patch_membership(updated) != 200:
                raise RuntimeError("Manager could not repair membership in the ConfigMap")
            changed = True
        after = _membership()
        return {"passes": passes, "changed": changed,
                "active": labels_for_membership(after, endpoints)["active"]}
    raise ValueError("Unknown fixed fixture operation")


def main(args):
    if len(args) == 2 and args[0] == "call":
        result = _call(args[1])
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return
    raise ValueError("Unknown fixture command")


if __name__ == "__main__":
    main(sys.argv[1:])
