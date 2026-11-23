"""Stdlib-only, CA-validating client for an owned Qdrant fixture."""
import hashlib
from pathlib import Path
import http.client
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import quote

PORT = 6333
MARKER = "synthetic-cedar-v1"


def https_context(trust=True):
    context = ssl.create_default_context(cafile="/trust/ca.crt" if trust else None)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def request(host, path, api_key, method="GET", payload=None):
    data = None if payload is None else json.dumps(payload, sort_keys=True,
        separators=(",", ":")).encode("utf-8")
    headers = {"api-key": api_key}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"https://{host}:{PORT}{path}", data=data,
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=https_context(), timeout=8) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        # Never emit an HTTP body or credential into fixture evidence.
        error.read()
        return error.code, {}


def tls_probe(host):
    context = https_context()
    with socket.create_connection((host, PORT), timeout=6) as raw:
        with context.wrap_socket(raw, server_hostname=host) as secured:
            return secured.version()


def negatives(host):
    try:
        with socket.create_connection((host, PORT), timeout=6) as raw:
            with https_context(trust=False).wrap_socket(raw, server_hostname=host):
                untrusted_rejected = False
    except ssl.SSLCertVerificationError:
        untrusted_rejected = True

    plain_req = urllib.request.Request(f"http://{host}:{PORT}/collections", method="GET")
    try:
        with urllib.request.urlopen(plain_req, timeout=6) as response:
            response.read()
            plaintext_rejected = False
    except (urllib.error.URLError, OSError, http.client.HTTPException):
        plaintext_rejected = True
    return untrusted_rejected, plaintext_rejected


def read_marker(host, collection, api_key):
    status, body = request(host, f"/collections/{collection}/points/scroll", api_key,
        method="POST", payload={"limit": 5, "with_payload": True, "with_vector": True})
    rows = body.get("result", {}).get("points", [])
    return status == 200 and any(
        row.get("id") == 1 and row.get("payload", {}).get("marker") == MARKER
        and row.get("vector") == [0.25,0.75]
        for row in rows)


WORK = Path("/backup-work")


def baseline_read():
    with urllib.request.urlopen("http://fixture-qdrant-plain.saf-test.svc:6333/collections", timeout=8) as response:
        result = json.load(response)
        return response.status == 200 and result["status"] == "ok"


def capture(host, collection, key):
    status, response = request(host, f"/collections/{collection}/snapshots?wait=true", key, method="POST")
    if status != 200:
        raise RuntimeError(f"native snapshot creation returned {status}")
    name = quote(response["result"]["name"], safe="")
    path = f"/collections/{collection}/snapshots/{name}"
    req = urllib.request.Request(f"https://{host}:{PORT}{path}", headers={"api-key":key})
    with urllib.request.urlopen(req, context=https_context(), timeout=18) as handle:
        data = handle.read(16*1024*1024+1)
    if not data or len(data) > 16*1024*1024 or data[257:262] != b"ustar":
        raise RuntimeError("the bounded snapshot is not the expected native archive")
    metadata = json.dumps({"length":len(data), "sha256":hashlib.sha256(data).hexdigest(),
                           "marker":MARKER}, sort_keys=True).encode()
    raw = metadata.ljust(512,b" ") + data + b"\x00"*((-len(data))%512)
    (WORK/"plain.raw").write_bytes(raw)
    deleted, _ = request(host, path+"?wait=true", key, method="DELETE")
    if deleted != 200:
        raise RuntimeError("could not clear the exported source snapshot")
    return {"native_snapshot_captured":True}


def restore(host, key):
    raw = (WORK/"recovered.raw").read_bytes()
    meta = json.loads(raw[:512])
    snapshot = raw[512:512+meta["length"]]
    digest = hashlib.sha256(snapshot).hexdigest()
    if digest != meta["sha256"] or snapshot[257:262] != b"ustar":
        raise RuntimeError("decoded snapshot does not match its exact manifest")
    name = "fixture-transport-restored"
    boundary = "saf-owned-qdrant-snapshot-20261123"
    header = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"snapshot\"; "
              "filename=\"fixture.snapshot\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
    data = header + snapshot + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(
        f"https://{host}:{PORT}/collections/{name}/snapshots/upload?priority=snapshot&wait=true&checksum={digest}",
        data=data, headers={"api-key":key,"Content-Type":f"multipart/form-data; boundary={boundary}"},
        method="POST")
    with urllib.request.urlopen(req, context=https_context(), timeout=25) as response:
        restored = response.status == 200 and json.load(response)["result"] is True
    return {"snapshot_uploaded_and_restored":restored,
            "restored_collection_contains_exact_owned_point":read_marker(host,name,key)}


def main():
    operation, host, collection = sys.argv[1:4]
    api_key = open("/identity/api-key", encoding="utf-8").read().strip()
    if operation == "transport":
        version = tls_probe(host)
        status, _ = request(host, "/collections", api_key)
        untrusted, plaintext = negatives(host)
        print(json.dumps({"tls_verified": status == 200,
            "tls_version": version, "trusted_request_succeeded": status == 200,
            "baseline_accepts_plaintext": baseline_read(),
            "untrusted_certificate_rejected": untrusted,
            "plaintext_http_rejected": plaintext}, sort_keys=True))
        return

    if operation == "initialize":
        tls_version = tls_probe(host)
        collection_status, _ = request(host, "/collections/" + collection, api_key,
            method="PUT", payload={"vectors": {"size": 2, "distance": "Dot"}})
        point_status, _ = request(host, f"/collections/{collection}/points?wait=true", api_key,
            method="PUT", payload={"points": [{"id": 1, "vector": [0.25, 0.75],
                "payload": {"marker": MARKER, "fixture": "owned-synthetic"}}]})
        read_ok = read_marker(host, collection, api_key)
        ok = collection_status in (200, 201) and point_status in (200, 201) and read_ok
        print(json.dumps({"tls_verified": True, "hostname_verified": True,
            "tls_version": tls_version, "write_and_read_ok": ok}, sort_keys=True))
        return

    if operation in ("capture", "restore"):
        result = capture(host, collection, api_key) if operation == "capture" else restore(host, api_key)
        print(json.dumps(result, sort_keys=True))
        return

    if operation == "recover":
        found = read_marker(host, collection, api_key)
        print(json.dumps({"recovered": found, "marker": MARKER if found else None}, sort_keys=True))
        return

    raise SystemExit("unknown fixture operation")


if __name__ == "__main__":
    main()
