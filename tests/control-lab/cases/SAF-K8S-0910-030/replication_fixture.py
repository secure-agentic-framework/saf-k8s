"""Fixed OCI replication client and narrow mTLS ingress for SAF-K8S-0910-030."""
from hashlib import sha256
from http.client import HTTPConnection, HTTPResponse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import base64
import gzip
import io
import json
from pathlib import Path
import socket
import ssl
import sys
import tarfile
import time
from urllib.parse import urlsplit

REPOSITORY = "fixtures/saf-replication"
TAG = "fixture-v1"
MEDIA = "application/vnd.docker.distribution.manifest.v2+json"
APPROVED_URI = "spiffe://saf.test/ns/saf-test/sa/fixture-replication-approved"
OTHER_URI = "spiffe://saf.test/ns/saf-test/sa/fixture-replication-other"
DNS = "registry-peer.saf.test"
SERVER_URI = "spiffe://saf.test/ns/saf-test/sa/fixture-replication-destination"


def digest(data):
    return "sha256:" + sha256(data).hexdigest()


def artifact():
    content = b"SAF inert registry replication fixture v1\n"
    raw = io.BytesIO()
    info = tarfile.TarInfo("fixture.txt")
    info.size, info.mode, info.mtime = len(content), 0o644, 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(info, io.BytesIO(content))
    layer = gzip.compress(raw.getvalue(), mtime=0)
    config = json.dumps({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers",
                        "diff_ids": [digest(raw.getvalue())]}, "config": {}},
                        sort_keys=True, separators=(",", ":")).encode()
    manifest = json.dumps({"schemaVersion": 2, "mediaType": MEDIA,
        "config": {"mediaType": "application/vnd.docker.container.image.v1+json",
                   "size": len(config), "digest": digest(config)},
        "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "size": len(layer), "digest": digest(layer)}]},
        sort_keys=True, separators=(",", ":")).encode()
    return {"manifest": manifest, "config": config, "layer": layer}


ARTIFACT = artifact()
MANIFEST_DIGEST = digest(ARTIFACT["manifest"])


def client_context(cert=True):
    context = ssl.create_default_context(cafile="/trust/ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if cert and Path("/credential/tls.crt").is_file():
        context.load_cert_chain("/credential/tls.crt", "/credential/tls.key")
    return context


def _fixed_call(host, port, operation, cert=True, hostname=DNS):
    context = client_context(cert)
    try:
        with socket.create_connection((host, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as tls:
                peer_uris = [value for scheme, value in tls.getpeercert().get("subjectAltName", ())
                             if scheme == "URI"]
                if peer_uris != [SERVER_URI]:
                    return {"status": "server-uri-refused"}
                if not cert:
                    # With TLS 1.3 the server's certificate_required alert can arrive after
                    # the client's handshake returns. Read that alert before sending data.
                    tls.recv(1)
                    return {"status": "client-certificate-alert-missing"}
                data = source_artifact() if operation == "replicate" else ARTIFACT
                body = b"{}" if operation != "replicate" else json.dumps({
                    "repository": REPOSITORY, "tag": TAG,
                    "blobs": {key: base64.b64encode(value).decode("ascii") for key, value in data.items()},
                    "manifest_digest": digest(data["manifest"]),
                }, sort_keys=True, separators=(",", ":")).encode()
                path = "/replicate" if operation == "replicate" else "/health"
                tls.sendall((f"POST {path} HTTP/1.1\r\nHost: {DNS}\r\nContent-Type: application/json\r\n"
                             f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body)
                response = HTTPResponse(tls)
                response.begin()
                payload = response.read(1024 * 1024)
                return {"status": response.status, "body": json.loads(payload) if payload else None}
    except ssl.SSLCertVerificationError as error:
        if error.verify_code == 62:
            return {"status": "server-identity-refused"}
        return {"status": "certificate-verification-failed", "verify_code": error.verify_code}
    except ssl.SSLError as error:
        if error.reason == "TLSV13_ALERT_CERTIFICATE_REQUIRED":
            return {"status": "client-certificate-refused"}
        return {"status": "tls-refused", "reason": error.reason}
    except OSError:
        return {"status": "transport-unavailable"}


def registry_request(method, path, body=None, headers=None, host="127.0.0.1"):
    # The only non-loopback target is the fixed source Distribution Service in this cluster.
    if host not in ("127.0.0.1", "fixture-replication-source.saf-test.svc"):
        raise ValueError("registry host is outside the fixed fixture endpoints")
    connection = HTTPConnection(host, 5000, timeout=6)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise ValueError("fixture response exceeds byte cap")
        return response.status, data, dict(response.getheaders())
    finally:
        connection.close()


def push_blob(blob, expected, host="127.0.0.1"):
    if digest(blob) != expected:
        raise ValueError("fixture blob digest mismatch")
    status, _, headers = registry_request("POST", f"/v2/{REPOSITORY}/blobs/uploads/", b"", host=host)
    if status != 202:
        raise RuntimeError("Distribution did not start the fixed upload")
    location = headers.get("Location", "")
    parsed = urlsplit(location)
    prefix = f"/v2/{REPOSITORY}/blobs/uploads/"
    if (parsed.netloc and parsed.hostname != host) or not parsed.path.startswith(prefix) or \
       ".." in parsed.path.split("/"):
        raise RuntimeError("Distribution returned an out-of-scope upload location")
    query = parsed.query + ("&" if parsed.query else "") + "digest=" + expected
    status, _, headers = registry_request("PUT", parsed.path + "?" + query, blob,
        {"Content-Type": "application/octet-stream"}, host=host)
    if status != 201 or headers.get("Docker-Content-Digest") != expected:
        raise RuntimeError("Distribution did not confirm the fixed blob digest")


def receive(payload):
    if set(payload) != {"repository", "tag", "blobs", "manifest_digest"} or \
       payload["repository"] != REPOSITORY or payload["tag"] != TAG:
        raise ValueError("request is outside the fixed fixture repository and tag")
    blobs = {key: base64.b64decode(value, validate=True) for key, value in payload["blobs"].items()}
    if blobs != ARTIFACT or payload["manifest_digest"] != MANIFEST_DIGEST:
        raise ValueError("request bytes do not match the locked inert OCI fixture")
    for key, expected in (("config", digest(ARTIFACT["config"])), ("layer", digest(ARTIFACT["layer"]))):
        push_blob(blobs[key], expected)
    status, _, headers = registry_request("PUT", f"/v2/{REPOSITORY}/manifests/{TAG}",
        blobs["manifest"], {"Content-Type": MEDIA, "Content-Length": str(len(blobs["manifest"]))})
    if status != 201 or headers.get("Docker-Content-Digest") != MANIFEST_DIGEST:
        raise RuntimeError("Distribution did not confirm the fixed manifest digest")
    return {"decision": "replicated", "digest": MANIFEST_DIGEST}


def source_artifact():
    status, body, headers = registry_request("GET", f"/v2/{REPOSITORY}/manifests/{TAG}",
        headers={"Accept": MEDIA}, host="fixture-replication-source.saf-test.svc")
    if status != 200 or digest(body) != MANIFEST_DIGEST or \
       headers.get("Docker-Content-Digest") != MANIFEST_DIGEST or body != ARTIFACT["manifest"]:
        raise RuntimeError("source Distribution did not return the locked manifest")
    result = {"manifest": body}
    for name, blob_digest in (("config", digest(ARTIFACT["config"])), ("layer", digest(ARTIFACT["layer"]))):
        status, blob, _ = registry_request("GET", f"/v2/{REPOSITORY}/blobs/{blob_digest}",
            host="fixture-replication-source.saf-test.svc")
        if status != 200 or digest(blob) != blob_digest or blob != ARTIFACT[name]:
            raise RuntimeError("source Distribution blob did not match its locked digest")
        result[name] = blob
    return result


def wait_source_registry():
    host = "fixture-replication-source.saf-test.svc"
    deadline = time.monotonic() + 14
    while time.monotonic() < deadline:
        try:
            if registry_request("GET", "/v2/", host=host)[0] == 200:
                return
        except (ConnectionRefusedError, TimeoutError):
            pass
        time.sleep(0.2)
    raise RuntimeError("The case-owned source registry Service never became reachable")


def seed_source():
    wait_source_registry()
    for key, expected in (("config", digest(ARTIFACT["config"])), ("layer", digest(ARTIFACT["layer"]))):
        push_blob(ARTIFACT[key], expected, host="fixture-replication-source.saf-test.svc")
    status, _, headers = registry_request("PUT", f"/v2/{REPOSITORY}/manifests/{TAG}",
        ARTIFACT["manifest"], {"Content-Type": MEDIA, "Content-Length": str(len(ARTIFACT["manifest"]))},
        host="fixture-replication-source.saf-test.svc")
    if status != 201 or headers.get("Docker-Content-Digest") != MANIFEST_DIGEST:
        raise RuntimeError("source Distribution did not confirm the locked manifest")
    return {"digest": MANIFEST_DIGEST}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
        print(json.dumps({"status": status, **value}, sort_keys=True), flush=True)

    def do_POST(self):
        if self.path == "/health":
            return self.reply(200, {"decision": "ready"})
        if self.path != "/replicate" or self.server.mode not in ("baseline", "restricted"):
            return self.reply(404, {"decision": "refused"})
        length = int(self.headers.get("Content-Length", "-1"))
        if length < 0 or length > 1024 * 1024:
            return self.reply(413, {"decision": "refused"})
        cert = self.connection.getpeercert()
        uris = [value for scheme, value in cert.get("subjectAltName", ()) if scheme == "URI"]
        who = uris[0] if len(uris) == 1 else None
        if self.server.mode == "restricted" and who != APPROVED_URI:
            return self.reply(403, {"decision": "identity-refused", "peer_uri": who})
        try:
            result = receive(json.loads(self.rfile.read(length)))
            return self.reply(201, {**result, "peer_uri": who})
        except (TypeError, ValueError):
            return self.reply(400, {"decision": "fixture-rejected"})
        except (OSError, RuntimeError):
            return self.reply(502, {"decision": "registry-unavailable"})


def serve(mode):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain("/credential/tls.crt", "/credential/tls.key")
    context.load_verify_locations("/trust/ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    server.mode = mode
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def observe():
    status, body, headers = registry_request("GET", f"/v2/{REPOSITORY}/manifests/{TAG}",
        headers={"Accept": MEDIA})
    if status == 404:
        references = (f"manifests/{MANIFEST_DIGEST}", f"blobs/{digest(ARTIFACT['config'])}",
                      f"blobs/{digest(ARTIFACT['layer'])}")
        if any(registry_request("GET", f"/v2/{REPOSITORY}/{ref}")[0] != 404 for ref in references):
            raise RuntimeError("Destination contains fixture bytes even though the tag is absent")
        return {"digest": None, "status": 404}
    actual = digest(body)
    advertised = headers.get("Docker-Content-Digest")
    if status != 200 or actual != advertised or actual != MANIFEST_DIGEST or body != ARTIFACT["manifest"]:
        raise RuntimeError("Destination Distribution manifest readback mismatch")
    for key, expected in (("config", digest(ARTIFACT["config"])), ("layer", digest(ARTIFACT["layer"]))):
        blob_status, blob, _ = registry_request("GET", f"/v2/{REPOSITORY}/blobs/{expected}")
        if blob_status != 200 or digest(blob) != expected or blob != ARTIFACT[key]:
            raise RuntimeError("Destination Distribution blob readback mismatch")
    return {"digest": actual, "status": status}


if __name__ == "__main__":
    command = sys.argv[1]
    if command == "serve":
        serve(sys.argv[2])
    elif command == "call":
        _, _, host, port, op, cert, hostname = sys.argv
        print(json.dumps(_fixed_call(host, int(port), op, cert == "cert", hostname), sort_keys=True))
    elif command == "observe":
        print(json.dumps(observe(), sort_keys=True))
    elif command == "seed":
        print(json.dumps(seed_source(), sort_keys=True))
