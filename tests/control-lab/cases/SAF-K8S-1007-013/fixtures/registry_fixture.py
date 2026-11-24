"""Push/read tiny deterministic OCI artifacts from the in-cluster registry only."""
import hashlib
import json
import sys
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


ROOT, REPOSITORY, TAG, ACTION, *ARGS = sys.argv[1:]
ALLOWED_HOST = urlsplit(ROOT).hostname
if ALLOWED_HOST != "distribution-registry.saf-1007-013-owned.svc.cluster.local":
    raise SystemExit("registry fixture URL is outside the owned in-cluster Service")



class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


opener = build_opener(ProxyHandler({}), NoRedirect())


def request(method, path, data=None, headers=None):
    url = path if path.startswith("http://") else urljoin(ROOT + "/", path.lstrip("/"))
    parts = urlsplit(url)
    if parts.scheme != "http" or parts.hostname != ALLOWED_HOST or parts.port != 5000:
        raise SystemExit("refusing a Registry API request outside the local fixture Service")
    req = Request(url, data=data, headers=headers or {}, method=method)
    with opener.open(req, timeout=10) as response:
        return response.status, response.headers, response.read()


def put_blob(content):
    _, headers, _ = request("POST", f"/v2/{REPOSITORY}/blobs/uploads/")
    location = headers.get("Location")
    if not location:
        raise RuntimeError("registry did not return the blob upload Location")
    # Distribution returns an upload URL on this same in-cluster service.
    upload = urljoin(ROOT + "/", location)
    parts = urlsplit(upload)
    if parts.scheme != "http" or parts.hostname != ALLOWED_HOST or parts.port != 5000:
        raise SystemExit("refusing a blob upload outside the local fixture Service")
    _, headers, _ = request("PATCH", upload, content,
                            {"Content-Type": "application/octet-stream"})
    location = headers.get("Location", upload)
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    final_url = urljoin(ROOT + "/", location)
    parts = urlsplit(final_url)
    if parts.scheme != "http" or parts.hostname != ALLOWED_HOST or parts.port != 5000:
        raise SystemExit("refusing a blob finalization outside the local fixture Service")
    separator = "&" if "?" in final_url else "?"
    request("PUT", final_url + separator + "digest=" + digest, b"",
            {"Content-Length": "0"})
    return digest


def push(revision):
    revision_text = f"SYNTH-REVISION-{revision:03d}"
    config = json.dumps({"artifactType": "application/vnd.saf.synthetic.model.v1",
                         "revision": revision_text}, sort_keys=True,
                        separators=(",", ":")).encode()
    payload = ("SYNTHETIC-OCI-MODEL-METADATA\n" + revision_text + "\n").encode()
    config_digest = put_blob(config)
    payload_digest = put_blob(payload)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.saf.synthetic.model.v1",
        "config": {"mediaType": "application/vnd.saf.synthetic.model-config.v1+json",
                   "digest": config_digest, "size": len(config)},
        "layers": [{"mediaType": "application/vnd.saf.synthetic.model-metadata.v1+json",
                    "digest": payload_digest, "size": len(payload)}],
        "annotations": {"org.opencontainers.image.title": "SYNTH-MODEL-001",
                        "saf-k8s.example/revision": revision_text},
    }
    body = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    local_digest = "sha256:" + hashlib.sha256(body).hexdigest()
    status, _, _ = request(
        "PUT", f"/v2/{REPOSITORY}/manifests/{TAG}", body,
        {"Content-Type": "application/vnd.oci.image.manifest.v1+json"},
    )
    print(json.dumps({"action": "push", "revision": revision_text,
                      "manifest_digest": local_digest, "layer_digest": payload_digest,
                      "registry_status": status}, sort_keys=True))


def read():
    _, headers, body = request(
        "GET", f"/v2/{REPOSITORY}/manifests/{TAG}",
        headers={"Accept": "application/vnd.oci.image.manifest.v1+json"},
    )
    manifest = json.loads(body)
    digest = headers.get("Docker-Content-Digest")
    if not digest:
        raise RuntimeError("Registry API response omitted Docker-Content-Digest")
    computed = "sha256:" + hashlib.sha256(body).hexdigest()
    layer = manifest["layers"][0]
    _, _, blob = request("GET", f"/v2/{REPOSITORY}/blobs/{layer['digest']}")
    _, _, config_bytes = request("GET", f"/v2/{REPOSITORY}/blobs/{manifest['config']['digest']}")
    if "sha256:" + hashlib.sha256(blob).hexdigest() != layer["digest"]:
        raise ValueError("Registry layer does not match its descriptor digest")
    if "sha256:" + hashlib.sha256(config_bytes).hexdigest() != manifest["config"]["digest"]:
        raise ValueError("Registry configuration does not match its descriptor digest")
    config = json.loads(config_bytes)
    payload_lines = blob.decode("ascii").splitlines()
    revision = manifest.get("annotations", {}).get("saf-k8s.example/revision")
    print(json.dumps({
        "action": "read", "repository": REPOSITORY, "reference": TAG,
        "registry_digest_header": digest, "computed_manifest_digest": computed,
        "manifest_digest": digest, "manifest_media_type": manifest["mediaType"],
        "revision": revision, "config_revision": config["revision"],
        "blob_digest": layer["digest"], "blob_revision": payload_lines[-1],
        "blob_bytes": len(blob), "synthetic_marker": payload_lines[0],
    }, sort_keys=True))


if ACTION == "push":
    if len(ARGS) != 1 or ARGS[0] not in ("1", "2"):
        raise SystemExit("push accepts only deterministic fixture revisions 1 or 2")
    push(int(ARGS[0]))
elif ACTION == "read":
    read()
else:
    raise SystemExit("unsupported registry fixture action")
