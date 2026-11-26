"""Case-local OCI archive/restore witness over fixed inert bytes only."""
import hashlib
import json
from urllib.error import HTTPError
from urllib.parse import urljoin, urlparse, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener


BASE = "http://model-archive.saf-test.svc.cluster.local:5000"
SOURCE_REPO = "saf-test/model-retire"
ARCHIVE_REPO = "saf-test/model-archive"
SOURCE_TAG = "release-v1"
ARCHIVE_TAG = "archive-v1"
RESTORE_TAG = "restored-v1"
MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"
LAYER_TYPE = "application/vnd.saf.fixture.model-bytes.v1"
CONFIG_TYPE = "application/vnd.oci.empty.v1+json"
LINEAGE_VERSION = "fixture-lineage-v1"
LINEAGE_SOURCE = "fixture-dataset"
LINEAGE_NODE = "model-archive"
ARTIFACT_BYTES = b"SAF inert model artifact fixture v1\n"
CONFIG_BYTES = b"{}"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


OPENER = build_opener(NoRedirect())


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def request(method, url, body=None, media=None):
    parsed = urlparse(url)
    base = urlparse(BASE)
    if parsed.scheme != base.scheme or parsed.netloc != base.netloc:
        raise ValueError("endpoint-scope")
    headers = {"Accept": MANIFEST_TYPE}
    if media:
        headers["Content-Type"] = media
    request_obj = Request(url, data=body, headers=headers, method=method)
    try:
        with OPENER.open(request_obj, timeout=8) as response:
            return response.status, dict(response.headers.items()), response.read()
    except HTTPError as error:
        return error.code, dict(error.headers.items()), error.read()


def upload_blob(repository, data):
    expected = digest(data)
    root = f"{BASE}/v2/{repository}/blobs"
    status, headers, _ = request("POST", root + "/uploads/", b"")
    if status != 202 or "Location" not in headers:
        raise ValueError("upload-start")
    location = urljoin(BASE + "/", headers["Location"])
    parsed = urlparse(location)
    base = urlparse(BASE)
    if (parsed.scheme != base.scheme or parsed.netloc != base.netloc
            or not parsed.path.startswith(f"/v2/{repository}/blobs/uploads/")):
        raise ValueError("upload-location-scope")
    location += ("&" if "?" in location else "?") + urlencode({"digest": expected})
    status, _, _ = request("PUT", location, data, "application/octet-stream")
    if status != 201:
        raise ValueError("upload-complete")
    return expected


def manifest_bytes(layer_digest):
    value = {
        "schemaVersion": 2,
        "mediaType": MANIFEST_TYPE,
        "artifactType": "application/vnd.saf.fixture.model.v1",
        "annotations": {
            "org.opencontainers.image.title": "saf-inert-lineage-fixture",
            "org.opencontainers.image.version": "1.0.0",
            "saf-k8s.example/lineage-version": LINEAGE_VERSION,
            "saf-k8s.example/lineage-source": LINEAGE_SOURCE,
            "saf-k8s.example/lineage-node": LINEAGE_NODE,
        },
        "config": {"mediaType": CONFIG_TYPE, "digest": digest(CONFIG_BYTES),
                   "size": len(CONFIG_BYTES)},
        "layers": [{"mediaType": LAYER_TYPE, "digest": layer_digest,
                    "size": len(ARTIFACT_BYTES)}],
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def put_manifest(repository, reference, body):
    status, _, _ = request("PUT", f"{BASE}/v2/{repository}/manifests/{reference}",
                           body, MANIFEST_TYPE)
    return status


def get_manifest(repository, reference, expected_status=200):
    status, _, body = request("GET", f"{BASE}/v2/{repository}/manifests/{reference}")
    if status != expected_status:
        raise ValueError("manifest-read-status")
    return body


def get_blob(repository, blob_digest):
    status, _, body = request("GET", f"{BASE}/v2/{repository}/blobs/{blob_digest}")
    if status != 200:
        raise ValueError("blob-read-status")
    return body


def run():
    layer_digest = digest(ARTIFACT_BYTES)
    expected_manifest = manifest_bytes(layer_digest)
    manifest_digest = digest(expected_manifest)

    source_config = upload_blob(SOURCE_REPO, CONFIG_BYTES)
    source_layer = upload_blob(SOURCE_REPO, ARTIFACT_BYTES)
    if source_config != digest(CONFIG_BYTES) or source_layer != layer_digest:
        raise ValueError("source-blob-digest")
    source_publish = put_manifest(SOURCE_REPO, SOURCE_TAG, expected_manifest)
    source_read = get_manifest(SOURCE_REPO, SOURCE_TAG)
    source_ok = source_publish == 201 and digest(source_read) == manifest_digest

    archive_config = upload_blob(ARCHIVE_REPO, get_blob(SOURCE_REPO, source_config))
    archive_layer_data = get_blob(SOURCE_REPO, source_layer)
    archive_layer = upload_blob(ARCHIVE_REPO, archive_layer_data)
    archive_publish = put_manifest(ARCHIVE_REPO, ARCHIVE_TAG, source_read)
    archive_read = get_manifest(ARCHIVE_REPO, ARCHIVE_TAG)
    archive_ok = (archive_config == source_config and archive_layer == layer_digest
                  and archive_publish == 201 and digest(archive_read) == manifest_digest)

    delete_status, _, _ = request(
        "DELETE", f"{BASE}/v2/{SOURCE_REPO}/manifests/{manifest_digest}")
    source_digest_absent = False
    source_tag_absent = False
    try:
        get_manifest(SOURCE_REPO, manifest_digest, expected_status=404)
        source_digest_absent = True
    except ValueError:
        source_digest_absent = False
    try:
        get_manifest(SOURCE_REPO, SOURCE_TAG, expected_status=404)
        source_tag_absent = True
    except ValueError:
        source_tag_absent = False
    source_absent = source_digest_absent and source_tag_absent

    archived_manifest = get_manifest(ARCHIVE_REPO, manifest_digest)
    archived_obj = json.loads(archived_manifest)
    archived_layer_digest = archived_obj["layers"][0]["digest"]
    archived_config_digest = archived_obj["config"]["digest"]
    archived_config = get_blob(ARCHIVE_REPO, archived_config_digest)
    archived_layer = get_blob(ARCHIVE_REPO, archived_layer_digest)
    lineage = archived_obj.get("annotations", {})
    archive_readback = (digest(archived_manifest) == manifest_digest
                        and archived_config == CONFIG_BYTES
                        and digest(archived_layer) == layer_digest
                        and archived_layer == ARTIFACT_BYTES
                        and lineage.get("saf-k8s.example/lineage-version") == LINEAGE_VERSION
                        and lineage.get("saf-k8s.example/lineage-source") == LINEAGE_SOURCE
                        and lineage.get("saf-k8s.example/lineage-node") == LINEAGE_NODE)

    # Restore exclusively from bytes read back from the archive repository.
    restored_config = upload_blob(SOURCE_REPO, archived_config)
    restored_layer = upload_blob(SOURCE_REPO, archived_layer)
    restore_publish = put_manifest(SOURCE_REPO, RESTORE_TAG, archived_manifest)
    restored_manifest = get_manifest(SOURCE_REPO, RESTORE_TAG)
    restored_obj = json.loads(restored_manifest)
    restored_blob = get_blob(SOURCE_REPO, restored_obj["layers"][0]["digest"])
    restore_ok = (restored_config == archived_config_digest
                  and restored_layer == layer_digest
                  and restore_publish == 201
                  and digest(restored_manifest) == manifest_digest
                  and restored_blob == ARTIFACT_BYTES
                  and digest(restored_blob) == layer_digest)

    return {
        "source_publish_status": source_publish,
        "source_pull_digest_matches": source_ok,
        "archive_publish_status": archive_publish,
        "archive_manifest_digest": digest(archive_read),
        "source_delete_status": delete_status,
        "source_manifest_absent_after_retirement": source_absent,
        "source_digest_absent_after_retirement": source_digest_absent,
        "source_tag_absent_after_retirement": source_tag_absent,
        "archive_readback_matches": archive_readback,
        "archive_manifest_digest_after_retirement": digest(archived_manifest),
        "layer_sha256": hashlib.sha256(archived_layer).hexdigest(),
        "layer_bytes_match": archived_layer == ARTIFACT_BYTES,
        "lineage_version": lineage.get("saf-k8s.example/lineage-version"),
        "lineage_source": lineage.get("saf-k8s.example/lineage-source"),
        "lineage_node": lineage.get("saf-k8s.example/lineage-node"),
        "restore_publish_status": restore_publish,
        "restored_manifest_digest": digest(restored_manifest),
        "restored_layer_sha256": hashlib.sha256(restored_blob).hexdigest(),
        "restore_matches": restore_ok,
        "only_case_service_endpoint": True,
        "raw_bytes_emitted": False,
        "scope": "one Zot instance; source and archive are separate repositories on the same ephemeral backend",
    }


if __name__ == "__main__":
    try:
        print(json.dumps(run(), sort_keys=True))
    except Exception as error:
        # Keep evidence safe and stable: no exception text or request bodies are emitted.
        print(json.dumps({"status": "error", "error_class": type(error).__name__}, sort_keys=True))
        raise SystemExit(1)
