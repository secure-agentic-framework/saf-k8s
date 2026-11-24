"""Bounded local-only Distribution fixture: seed, copy and substitute inert metadata."""
import base64
from hashlib import sha256
from http.client import HTTPConnection
import json
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit

REPO = "fixtures/model"
MEDIA = "application/vnd.oci.image.manifest.v1+json"
TYPE = "application/vnd.saf.fixture.model-metadata.v1+json"
STMT = "com.example.saf.lineage.statement"
SIG = "com.example.saf.lineage.signature"
MAX = 2 * 1024 * 1024


def digest(data):
    return "sha256:" + sha256(data).hexdigest()


def req(host, port, method, path, body=None, media=None):
    if len(path) > 2048 or (body is not None and len(body) > MAX):
        raise ValueError("bounded fixture request exceeded")
    conn = HTTPConnection(host, port, timeout=5)
    try:
        headers = {"Accept": MEDIA}
        if media:
            headers["Content-Type"] = media
        conn.request(method, path, body=body, headers=headers)
        res = conn.getresponse()
        body = res.read(MAX + 1)
        if len(body) > MAX:
            raise ValueError("bounded fixture response exceeded")
        return res.status, body, {k.lower(): v for k, v in res.getheaders()}
    finally:
        conn.close()


def upload_blob(host, port, blob):
    prefix = f"/v2/{REPO}/"
    status, _, headers = req(host, port, "POST", prefix + "blobs/uploads/", b"")
    if status != 202 or "location" not in headers:
        raise RuntimeError("local registry upload did not initialize")
    location = urlsplit(headers["location"])
    if not location.path.startswith(prefix + "blobs/uploads/"):
        raise RuntimeError("registry returned out-of-scope upload path")
    query = urlencode([*parse_qsl(location.query), ("digest", digest(blob))])
    status, _, _ = req(host, port, "PUT", location.path + "?" + query, blob,
                       "application/octet-stream")
    if status != 201:
        raise RuntimeError("local registry rejected fixture blob")


def seed(p):
    blob = json.dumps({"executable": False, "name": "fixture-linear-model",
                       "version": "1.0.0", "weights": "synthetic-placeholder"},
                      sort_keys=True, separators=(",", ":")).encode()
    statement = base64.b64decode(p["statement_b64"], validate=True)
    signature = base64.b64decode(p["signature_b64"], validate=True)
    manifest = {"schemaVersion": 2, "mediaType": MEDIA, "artifactType": TYPE,
                "config": {"mediaType": TYPE, "digest": digest(blob), "size": len(blob)},
                "layers": [], "annotations": {STMT: p["statement_b64"], SIG: p["signature_b64"]}}
    upload_blob(p["host"], p["port"], blob)
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    status, _, headers = req(p["host"], p["port"], "PUT", f"/v2/{REPO}/manifests/approved", raw, MEDIA)
    if status != 201:
        raise RuntimeError("source registry rejected manifest")
    return {"source_manifest_digest": digest(raw), "registry_manifest_digest": headers.get("docker-content-digest"),
            "blob_digest": digest(blob), "blob_b64": base64.b64encode(blob).decode()}


def copy(p):
    status, raw, headers = req(p["source_host"], p["source_port"], "GET", f"/v2/{REPO}/manifests/approved")
    if status != 200 or digest(raw) != headers.get("docker-content-digest"):
        raise ValueError("source manifest failed Distribution digest readback")
    manifest = json.loads(raw)
    desc = manifest["config"]
    status, blob, _ = req(p["source_host"], p["source_port"], "GET", f"/v2/{REPO}/blobs/{desc['digest']}")
    if status != 200 or len(blob) != desc["size"] or digest(blob) != desc["digest"]:
        raise ValueError("source blob failed descriptor readback")
    upload_blob(p["destination_host"], 5000, blob)
    status, _, _ = req(p["destination_host"], 5000, "PUT", f"/v2/{REPO}/manifests/copied", raw, MEDIA)
    if status != 201:
        raise RuntimeError("destination registry rejected copied manifest")
    return {"source_claimed_success": True, "reference": "copied", "manifest_digest": digest(raw),
            "blob_digest": digest(blob), "blob_b64": base64.b64encode(blob).decode()}


def substitute(p):
    status, raw, _ = req(p["destination_host"], 5000, "GET", f"/v2/{REPO}/manifests/copied")
    if status != 200:
        raise ValueError("copied destination manifest absent")
    manifest = json.loads(raw)
    # Benign metadata substitution only; keep the original source signature to create a mismatch.
    blob = json.dumps({"executable": False, "name": "fixture-linear-model",
                       "version": "1.0.0", "weights": "substituted-placeholder"},
                      sort_keys=True, separators=(",", ":")).encode()
    upload_blob(p["destination_host"], 5000, blob)
    manifest["config"] = {"mediaType": TYPE, "digest": digest(blob), "size": len(blob)}
    manifest["annotations"]["com.example.saf.fixture.source_claim"] = "transfer-success"
    substituted = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    status, _, _ = req(p["destination_host"], 5000, "PUT", f"/v2/{REPO}/manifests/copied", substituted, MEDIA)
    if status != 201:
        raise RuntimeError("destination registry rejected substituted fixture manifest")
    return {"reference": "copied", "source_claimed_success": True,
            "manifest_digest": digest(substituted), "blob_digest": digest(blob),
            "blob_b64": base64.b64encode(blob).decode()}


if __name__ == "__main__":
    op = sys.argv[1]
    p = json.load(sys.stdin)
    if op == "seed":
        out = seed(p)
    elif op == "copy":
        out = copy(p)
    elif op == "substitute":
        out = substitute(p)
    else:
        raise SystemExit("unknown operation")
    print(json.dumps(out, sort_keys=True))
