"""Fixed-endpoint artifact transfer gated by a separately written enrollment record."""
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
import time
import tarfile
from urllib.parse import urlsplit

NS = "saf-test"
SOURCE_NAME = "fixture-enrollment-source"
APPROVED_NAME = "fixture-enrollment-approved"
UNAPPROVED_NAME = "fixture-enrollment-unapproved"
APPROVAL = "/api/v1/namespaces/saf-test/configmaps/fixture-endpoint-enrollment-approval"
REQUEST = "/api/v1/namespaces/saf-test/configmaps/fixture-endpoint-enrollment-request"
SOURCE_CLAIM = "/api/v1/namespaces/saf-test/configmaps/fixture-source-owner-claim"
DESTINATION_CLAIM = "/api/v1/namespaces/saf-test/configmaps/fixture-destination-owner-claim"
REPOSITORY = "fixtures/saf-endpoint-enrollment"
TAG = "inert-v1"
MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"


def _layer():
    content = b"SAF endpoint enrollment inert artifact v1\n"
    output = io.BytesIO()
    info = tarfile.TarInfo("fixture.txt")
    info.size = len(content)
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(info, io.BytesIO(content))
    uncompressed = output.getvalue()
    return uncompressed, gzip.compress(uncompressed, mtime=0)


UNCOMPRESSED_LAYER, LAYER = _layer()


def _digest(data):
    return "sha256:" + sha256(data).hexdigest()


LAYER_DIFF_ID = _digest(UNCOMPRESSED_LAYER)
LAYER_DIGEST = _digest(LAYER)
CONFIG = json.dumps({"architecture": "amd64", "os": "linux",
                     "rootfs": {"type": "layers", "diff_ids": [LAYER_DIFF_ID]},
                     "config": {}}, sort_keys=True, separators=(",", ":")).encode()
CONFIG_DIGEST = _digest(CONFIG)
MANIFEST = json.dumps({
    "schemaVersion": 2,
    "mediaType": MEDIA_TYPE,
    "config": {"mediaType": "application/vnd.docker.container.image.v1+json",
               "size": len(CONFIG), "digest": CONFIG_DIGEST},
    "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(LAYER), "digest": LAYER_DIGEST}],
}, sort_keys=True, separators=(",", ":")).encode()
MANIFEST_DIGEST = _digest(MANIFEST)


def endpoint_map(peer_ip, approved_port, unapproved_port):
    ip = ipaddress.ip_address(str(peer_ip))
    approved_port = int(approved_port)
    unapproved_port = int(unapproved_port)
    if (ip.version != 4 or ip.is_global or ip.is_loopback or ip.is_link_local
            or approved_port == unapproved_port
            or any(not 30000 <= port <= 32767 for port in (approved_port, unapproved_port))):
        raise ValueError("Endpoints are outside the two owned Kind fixture registries")
    return {
        "source": f"http://{SOURCE_NAME}.{NS}.svc:5000",
        "approved": f"http://{ip}:{approved_port}",
        "unapproved": f"http://{ip}:{unapproved_port}",
    }


def endpoints():
    return endpoint_map(os.environ["PEER_IP"], os.environ["APPROVED_PORT"],
                        os.environ["UNAPPROVED_PORT"])


def _endpoint(url, values):
    if url not in values.values():
        raise ValueError("Network destination is not a fixed case registry")
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.username or parsed.password or parsed.query
            or parsed.fragment or parsed.path):
        raise ValueError("Invalid fixed registry endpoint")
    return parsed


def _registry(url, method, path, values, body=None, headers=None):
    parsed = _endpoint(url, values)
    if not path.startswith("/v2/") or ".." in PurePosixPath(path).parts:
        raise ValueError("Request is outside the fixed Distribution API")
    connection = HTTPConnection(parsed.hostname, parsed.port, timeout=8)
    try:
        connection.request(method, path, body=body,
                           headers={"Host": parsed.netloc, **(headers or {})})
        response = connection.getresponse()
        data = response.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise ValueError("Registry response exceeds the fixture limit")
        return response.status, data, dict(response.getheaders())
    finally:
        connection.close()


def _api(method, path=APPROVAL, body=None):
    with open("/var/run/secrets/kubernetes.io/serviceaccount/token", encoding="utf-8") as token_file:
        token = token_file.read().strip()
    context = ssl.create_default_context(cafile="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    connection = HTTPSConnection("kubernetes.default.svc", 443, context=context, timeout=8)
    try:
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode() if body is not None else None
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        if raw is not None:
            headers["Content-Type"] = "application/merge-patch+json"
        connection.request(method, path, body=raw, headers=headers)
        response = connection.getresponse()
        data = response.read()
        return response.status, json.loads(data) if data else None
    finally:
        connection.close()


def _approval():
    status, record = _api("GET")
    if status == 404:
        return None
    if status != 200 or record.get("immutable") is True:
        raise RuntimeError("Could not read the mutable, RBAC-protected enrollment approval")
    raw = record.get("data", {}).get("approved-pair.json")
    return json.loads(raw) if raw else None


def _request():
    status, record = _api("GET", REQUEST)
    if status != 200 or record.get("immutable") is True:
        raise RuntimeError("Could not read the case enrollment request")
    raw = record.get("data", {}).get("requested-pair.json")
    return json.loads(raw) if raw else None


def _push_blob(endpoint, digest, blob, values):
    status, _, headers = _registry(endpoint, "POST", f"/v2/{REPOSITORY}/blobs/uploads/",
                                   values, headers={"Content-Length": "0"})
    location = headers.get("Location") or headers.get("location")
    if status != 202 or not location:
        raise RuntimeError("Destination upload did not start")
    parsed = _endpoint(endpoint, values)
    target = urlsplit(location)
    if (target.scheme not in ("", "http") or target.netloc not in ("", parsed.netloc)
            or target.username or target.password or target.fragment):
        raise RuntimeError("Upload URL escaped the fixed endpoint")
    prefix = f"/v2/{REPOSITORY}/blobs/uploads/"
    if (not target.path.startswith(prefix) or not target.path[len(prefix):]
            or ".." in PurePosixPath(target.path).parts):
        raise RuntimeError("Upload URL escaped the fixed repository")
    query = target.query + ("&" if target.query else "") + "digest=" + digest
    status, _, headers = _registry(endpoint, "PUT", target.path + "?" + query, values,
                                   body=blob, headers={"Content-Type": "application/octet-stream"})
    returned = headers.get("Docker-Content-Digest") or headers.get("docker-content-digest")
    if status != 201 or returned != digest:
        raise RuntimeError("Destination did not confirm the expected blob digest")


def _copy(source, destination, values):
    status, manifest, headers = _registry(
        source, "GET", f"/v2/{REPOSITORY}/manifests/{TAG}", values,
        headers={"Accept": MEDIA_TYPE})
    advertised = headers.get("Docker-Content-Digest") or headers.get("docker-content-digest")
    if status != 200 or manifest != MANIFEST or advertised != MANIFEST_DIGEST:
        raise RuntimeError("Source did not contain the locked inert manifest")
    for digest, expected in ((CONFIG_DIGEST, CONFIG), (LAYER_DIGEST, LAYER)):
        status, blob, _ = _registry(source, "GET", f"/v2/{REPOSITORY}/blobs/{digest}", values)
        if status != 200 or blob != expected or _digest(blob) != digest:
            raise RuntimeError("Source blob differs from the deterministic fixture")
        _push_blob(destination, digest, blob, values)
    status, _, headers = _registry(
        destination, "PUT", f"/v2/{REPOSITORY}/manifests/{TAG}", values,
        body=MANIFEST, headers={"Content-Type": MEDIA_TYPE,
                                "Content-Length": str(len(MANIFEST))})
    returned = headers.get("Docker-Content-Digest") or headers.get("docker-content-digest")
    if status != 201 or returned != MANIFEST_DIGEST:
        raise RuntimeError("Destination did not confirm the expected manifest digest")
    return {"decision": "baseline-written", "digest": MANIFEST_DIGEST}


def _observed(url, values):
    status, data, headers = _registry(
        url, "GET", f"/v2/{REPOSITORY}/manifests/{TAG}", values,
        headers={"Accept": MEDIA_TYPE})
    if status == 404:
        refs = (f"manifests/{MANIFEST_DIGEST}", f"blobs/{CONFIG_DIGEST}", f"blobs/{LAYER_DIGEST}")
        if any(_registry(url, "GET", f"/v2/{REPOSITORY}/{ref}", values)[0] != 404 for ref in refs):
            raise RuntimeError("Destination unexpectedly contains untagged fixture content")
        return {"digest": None, "status": 404}
    digest = _digest(data)
    advertised = headers.get("Docker-Content-Digest") or headers.get("docker-content-digest")
    if status != 200 or digest != advertised:
        raise RuntimeError("Observer readback returned an invalid manifest digest")
    for blob_digest, expected in ((CONFIG_DIGEST, CONFIG), (LAYER_DIGEST, LAYER)):
        blob_status, blob, _ = _registry(url, "GET", f"/v2/{REPOSITORY}/blobs/{blob_digest}", values)
        if blob_status != 200 or blob != expected or _digest(blob) != blob_digest:
            raise RuntimeError("Observer could not verify the transferred config and layer blobs")
    return {"digest": digest, "status": 200}


def _approve(pair):
    status, _ = _api("PATCH", APPROVAL, {"data": {"approved-pair.json": json.dumps(
        pair, sort_keys=True, separators=(",", ":"))}})
    return {"http_status": status}


def _submit(pair):
    status, _ = _api("PATCH", REQUEST, {"data": {"requested-pair.json": json.dumps(
        pair, sort_keys=True, separators=(",", ":"))}})
    return {"http_status": status}


def _owner_claim(path):
    status, record = _api("GET", path)
    if status != 200:
        return None
    raw = record.get("data", {}).get("endpoint-owner.json")
    return json.loads(raw) if raw else None


def _governed(destination_label, values):
    source, destination = values["source"], values[destination_label]
    record = _approval()
    if record is None:
        return {"decision": "denied-missing-approval"}
    # Compare the approved pair first so the existing wrong-pair denials remain stable.
    if record != {"source": source, "destination": destination}:
        return {"decision": "denied-endpoint-pair"}
    source_claim = _owner_claim(SOURCE_CLAIM)
    destination_claim = _owner_claim(DESTINATION_CLAIM)
    if source_claim != {"endpoint": source, "registry": "source",
                        "service_uid": os.environ["SOURCE_SERVICE_UID"]} or destination_claim != {
            "endpoint": values["approved"], "registry": "approved-destination",
            "service_uid": os.environ["DESTINATION_SERVICE_UID"]}:
        return {"decision": "denied-missing-endpoint-ownership"}
    result = _copy(source, destination, values)
    return {"decision": "allowed", "digest": result["digest"]}


def _submit_owner_claim(which, *, wrong_uid=False):
    if which == "source":
        path, record = SOURCE_CLAIM, {"endpoint": endpoints()["source"], "registry": "source",
                                      "service_uid": os.environ[
                                          "DESTINATION_SERVICE_UID" if wrong_uid else "SOURCE_SERVICE_UID"
                                      ]}
    elif which == "destination":
        path, record = DESTINATION_CLAIM, {"endpoint": endpoints()["approved"],
                                            "registry": "approved-destination", "service_uid": os.environ["DESTINATION_SERVICE_UID"]}
    else:
        raise ValueError("Unknown fixed endpoint claim")
    status, _ = _api("PATCH", path, {"data": {"endpoint-owner.json": json.dumps(
        record, sort_keys=True, separators=(",", ":"))}})
    return {"http_status": status}


def _call(operation):
    values = endpoints()
    source, approved, unapproved = values["source"], values["approved"], values["unapproved"]
    if operation == "wait-ready":
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                if all(_registry(url, "GET", "/v2/", values)[0] == 200 for url in values.values()):
                    return {"ready": True}
            except (ConnectionRefusedError, TimeoutError):
                pass
            time.sleep(0.25)
        return {"ready": False}
    if operation == "seed":
        # The deterministic fixture writes only to the source registry.
        for digest, blob in ((CONFIG_DIGEST, CONFIG), (LAYER_DIGEST, LAYER)):
            _push_blob(source, digest, blob, values)
        status, _, headers = _registry(
            source, "PUT", f"/v2/{REPOSITORY}/manifests/{TAG}", values, body=MANIFEST,
            headers={"Content-Type": MEDIA_TYPE, "Content-Length": str(len(MANIFEST))})
        returned = headers.get("Docker-Content-Digest") or headers.get("docker-content-digest")
        if status != 201 or returned != MANIFEST_DIGEST:
            raise RuntimeError("Source did not confirm the expected manifest digest")
        return {"digest": MANIFEST_DIGEST}
    if operation == "baseline-open-copy":
        return _copy(source, approved, values)
    if operation == "submit-wrong-pair":
        return _submit({"source": source, "destination": unapproved})
    if operation == "submit-wrong-source":
        return _submit({"source": unapproved, "destination": approved})
    if operation == "submit-exact-pair":
        return _submit({"source": source, "destination": approved})
    if operation == "try-enroll-wrong-role":
        return _approve({"source": source, "destination": approved})
    if operation == "approver-approve-request":
        pair = _request()
        if pair is None:
            return {"decision": "denied-missing-request"}
        return _approve(pair)
    if operation == "governed-copy-approved":
        return _governed("approved", values)
    if operation == "governed-copy-unapproved":
        return _governed("unapproved", values)
    if operation == "observe-source":
        return _observed(source, values)
    if operation == "observe-approved":
        return _observed(approved, values)
    if operation == "observe-unapproved":
        return _observed(unapproved, values)
    if operation == "observe-approval":
        return {"pair": _approval()}
    if operation == "claim-source-endpoint":
        return _submit_owner_claim("source")
    if operation == "claim-source-wrong-uid":
        return _submit_owner_claim("source", wrong_uid=True)
    if operation == "claim-destination-endpoint":
        return _submit_owner_claim("destination")
    if operation == "observe-owner-claims":
        return {"source": _owner_claim(SOURCE_CLAIM),
                "destination": _owner_claim(DESTINATION_CLAIM)}
    raise ValueError("Unknown fixed fixture operation")


def main(args):
    if len(args) == 2 and args[0] == "call":
        print(json.dumps(_call(args[1]), sort_keys=True, separators=(",", ":")))
        return
    raise ValueError("Unknown fixture command")


if __name__ == "__main__":
    main(sys.argv[1:])
