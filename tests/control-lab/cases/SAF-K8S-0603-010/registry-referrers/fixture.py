"""Publish and discover the exact signed OCI fixtures used by the Kubernetes verifier."""
import base64
import hashlib
import json
from pathlib import Path
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


REGISTRY_IMAGE = (
    "docker.io/library/registry:3.0.0@sha256:"
    "6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
REPOSITORY = "saf-fixture/digest-bound-sbom"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
EMPTY = b"{}"
EMPTY_DESC = {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2,
}
ARTIFACT_TYPE = "application/vnd.saf-k8s.signed-sbom.v1"
ENVELOPE_TYPE = "application/vnd.dsse.envelope.v1+json"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://cyclonedx.org/bom"


class FixtureError(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def descriptor(media_type, data):
    return {"mediaType": media_type, "digest": digest(data), "size": len(data)}


def run(*args, check=True, timeout=60, input_bytes=None):
    result = subprocess.run(args, input=input_bytes, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    if check and result.returncode:
        raise FixtureError(
            f"command failed ({result.returncode}): {args[0]} {args[1:]}: "
            f"{result.stderr.decode(errors='replace')[-1200:]}"
        )
    return result


class LocalRegistry:
    def __init__(self, context, work):
        self.context = context
        self.work = work
        self.inspect_context = ["docker", "--context", context]
        self.docker = None
        self.name = "saf-sbom-" + uuid.uuid4().hex[:12]
        self.volume = self.name + "-data"
        self.ca = work / "registry-ca.crt"
        self.base = None
        self.opener = None
        self.events = []
        self.image_id = None

    def docker_cmd(self, *args, **kwargs):
        return run(*self.docker, *args, **kwargs)

    def start(self):
        context_info = json.loads(run(*self.inspect_context, "context", "inspect", self.context).stdout)
        host = context_info[0]["Endpoints"]["docker"]["Host"]
        if not host.startswith("unix://"):
            raise FixtureError("Docker context must address a local Unix socket")
        config = self.work / "docker-config"
        config.mkdir(mode=0o700)
        self.docker = ["env", "-u", "DOCKER_CONTEXT", "-u", "DOCKER_HOST", "docker",
                       "--config", str(config), "--host", host]
        tls = self.work / "tls"
        tls.mkdir(mode=0o700)
        ca_key, leaf_key = self.work / "ca.key", tls / "tls.key"
        csr, leaf = self.work / "registry.csr", tls / "tls.crt"
        ext = self.work / "registry.ext"
        ext.write_text(
            "subjectAltName=IP:127.0.0.1,DNS:localhost\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n", encoding="ascii")
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "2", "-subj", "/CN=SAF local fixture CA", "-keyout",
            str(ca_key), "-out", str(self.ca), "-addext",
            "basicConstraints=critical,CA:TRUE", "-addext",
            "keyUsage=critical,keyCertSign,cRLSign", timeout=45)
        run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=localhost", "-keyout", str(leaf_key), "-out",
            str(csr), timeout=45)
        run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(self.ca),
            "-CAkey", str(ca_key), "-CAcreateserial", "-extfile", str(ext),
            "-days", "2", "-out", str(leaf), timeout=45)
        self.docker_cmd("pull", REGISTRY_IMAGE, timeout=300)
        self.image_id = self.docker_cmd(
            "image", "inspect", "--format", "{{.Id}}", REGISTRY_IMAGE
        ).stdout.decode().strip()
        repo_digests = json.loads(self.docker_cmd(
            "image", "inspect", "--format", "{{json .RepoDigests}}", REGISTRY_IMAGE
        ).stdout)
        if not any(row.endswith("@" + REGISTRY_IMAGE.rsplit("@", 1)[1]) for row in repo_digests):
            raise FixtureError("could not confirm the pinned registry image ID")
        self.docker_cmd("volume", "create", self.volume)
        self.docker_cmd("run", "--detach", "--name", self.name,
                        "--publish", "127.0.0.1::5000",
                        "--env", "REGISTRY_HTTP_TLS_CERTIFICATE=/tls/tls.crt",
                        "--env", "REGISTRY_HTTP_TLS_KEY=/tls/tls.key",
                        "--volume", f"{tls}:/tls:ro",
                        "--volume", f"{self.volume}:/var/lib/registry",
                        REGISTRY_IMAGE)
        port_text = self.docker_cmd(
            "inspect", self.name, "--format",
            '{{(index (index .NetworkSettings.Ports "5000/tcp") 0).HostPort}}'
        ).stdout.decode().strip()
        if not port_text.isdecimal():
            raise FixtureError("registry did not publish a loopback host port")
        self.base = f"https://127.0.0.1:{port_text}"
        ctx = ssl.create_default_context(cafile=str(self.ca))
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                status, _, _ = self.request("/v2/", "GET")
                if status == 200:
                    return
            except (urllib.error.URLError, TimeoutError, FixtureError):
                time.sleep(.25)
        raise FixtureError("local TLS registry did not become ready")

    def request(self, path, method="GET", body=None, content_type=None,
                accept=None, expected=(200,)):
        if not path.startswith("/"):
            raise FixtureError("internal API path must be absolute")
        parts = urllib.parse.urlsplit(path)
        safe_query = urllib.parse.urlencode([
            (key, "<redacted>" if key.lower() in {"_state", "token"} else value)
            for key, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        ])
        safe_path = parts.path + ("?" + safe_query if safe_query else "")
        headers = {}
        if content_type:
            headers["Content-Type"] = content_type
        if accept:
            headers["Accept"] = accept
        req = urllib.request.Request(self.base + path, data=body, method=method,
                                     headers=headers)
        try:
            with self.opener.open(req, timeout=12) as response:
                code, hdrs, data = response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            code, hdrs, data = error.code, error.headers, error.read()
        except (urllib.error.URLError, TimeoutError) as error:
            raise FixtureError(f"local registry request failed: {method} {path}: {error}") from error
        if code not in expected:
            raise FixtureError(f"unexpected registry status {code}: {method} {path}")
        self.events.append({
            "method": method, "path": safe_path, "status": code,
            "headers": {key: hdrs.get(key) for key in
                        ("Content-Type", "Docker-Content-Digest", "OCI-Subject")
                        if hdrs.get(key) is not None},
        })
        return code, hdrs, data

    def upload_blob(self, payload):
        start = f"/v2/{REPOSITORY}/blobs/uploads/"
        _, headers, _ = self.request(start, "POST", body=b"", expected=(202,))
        location = headers.get("Location")
        if not location:
            raise FixtureError("registry omitted blob upload Location")
        parsed = urllib.parse.urlsplit(urllib.parse.urljoin(self.base, location))
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise FixtureError("registry upload Location escaped loopback TLS")
        if not parsed.path.startswith(start):
            raise FixtureError("registry upload Location differs from the fixture repository")
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query.append(("digest", digest(payload)))
        path = parsed.path + "?" + urllib.parse.urlencode(query)
        self.request(path, "PUT", body=payload,
                     content_type="application/octet-stream", expected=(201,))

    def put_manifest(self, ref, raw):
        _, headers, _ = self.request(f"/v2/{REPOSITORY}/manifests/{ref}", "PUT",
                                     body=raw, content_type=OCI_MANIFEST,
                                     expected=(201,))
        return headers

    def stop(self):
        if self.docker is None:
            return
        self.docker_cmd("rm", "--force", self.name, check=False)
        self.docker_cmd("volume", "rm", self.volume, check=False)
        container = self.docker_cmd("inspect", self.name, check=False)
        volume = self.docker_cmd("volume", "inspect", self.volume, check=False)
        if container.returncode == 0 or volume.returncode == 0:
            raise FixtureError("disposable registry container or volume remains after cleanup")


def verify_download(envelope, expected, subject, work):
    if not envelope:
        raise FixtureError("downloaded SBOM envelope was empty")
    doc = json.loads(envelope)
    if doc.get("payloadType") != PAYLOAD_TYPE or len(doc.get("signatures", [])) != 1:
        raise FixtureError("downloaded DSSE envelope has unexpected shape")
    payload = base64.b64decode(doc["payload"], validate=True)
    sig = base64.b64decode(doc["signatures"][0]["sig"], validate=True)
    statement = json.loads(payload)
    if (payload != expected["payload"] or sig != expected["signature"]
            or statement.get("_type") != STATEMENT_TYPE
            or statement.get("predicateType") != PREDICATE_TYPE
            or statement["subject"][0]["digest"]["sha256"] != subject.removeprefix("sha256:")):
        raise FixtureError("downloaded statement does not match the signed SBOM and its subject")
    pae = (b"DSSEv1 " + str(len(PAYLOAD_TYPE)).encode() + b" " + PAYLOAD_TYPE.encode()
           + b" " + str(len(payload)).encode() + b" " + payload)
    sig_path, pae_path = work / "download.sig", work / "download.pae"
    pub = work / "approved-fixture.pub"
    pub.write_bytes(expected["public"])
    sig_path.write_bytes(sig)
    pae_path.write_bytes(pae)
    run("openssl", "dgst", "-sha256", "-verify", str(pub), "-signature",
        str(sig_path), str(pae_path), timeout=20)
    return payload


def referrer_tag(subject):
    algorithm, digest_hex = subject.split(":", 1)
    return f"{algorithm}-{digest_hex[:64]}"


def read_index(status, headers, raw):
    if status == 404:
        return {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": []}
    data = json.loads(raw)
    if data.get("schemaVersion") != 2 or data.get("mediaType") != OCI_INDEX:
        raise FixtureError("referrers lookup did not return an OCI image index")
    if headers.get("Content-Type", "").split(";", 1)[0] != OCI_INDEX:
        raise FixtureError("referrers response has the wrong Content-Type")
    return data


def tagged_index(reg, subject):
    return read_index(*reg.request(f"/v2/{REPOSITORY}/manifests/{referrer_tag(subject)}",
                                   accept=OCI_INDEX, expected=(200, 404)))


def referrers(reg, subject):
    status, headers, raw = reg.request(
        f"/v2/{REPOSITORY}/referrers/{urllib.parse.quote(subject, safe=':')}?artifactType="
        f"{urllib.parse.quote(ARTIFACT_TYPE, safe='')}", accept=OCI_INDEX, expected=(200, 404))
    if status == 404:
        return tagged_index(reg, subject), "oci-1.1-referrers-tag-fallback"
    return read_index(status, headers, raw), "native-referrers-api"


def attach(reg, subject_digest, subject_size, envelope):
    reg.upload_blob(EMPTY)
    reg.upload_blob(envelope)
    artifact = canonical({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "artifactType": ARTIFACT_TYPE,
        "config": EMPTY_DESC,
        "layers": [descriptor(ENVELOPE_TYPE, envelope)],
        "subject": {"mediaType": OCI_MANIFEST, "digest": subject_digest,
                    "size": subject_size},
    })
    headers = reg.put_manifest(digest(artifact), artifact)
    ack = headers.get("OCI-Subject")
    if ack is None:
        current = tagged_index(reg, subject_digest)
        entry = {**descriptor(OCI_MANIFEST, artifact), "artifactType": ARTIFACT_TYPE}
        if not any(row.get("digest") == entry["digest"] for row in current["manifests"]):
            current["manifests"].append(entry)
        reg.request(f"/v2/{REPOSITORY}/manifests/{referrer_tag(subject_digest)}", "PUT",
                    body=canonical(current), content_type=OCI_INDEX, expected=(201,))
    elif ack != subject_digest:
        raise FixtureError(f"registry acknowledged the wrong OCI subject: {ack!r}")
    return artifact


def store_image(reg, label, image):
    manifest = json.loads(image["manifest"])
    for blob in (manifest["config"], *manifest["layers"]):
        content = (image["layout"] / "blobs" / "sha256" / blob["digest"].removeprefix("sha256:")).read_bytes()
        if descriptor(blob["mediaType"], content) != blob:
            raise FixtureError("local OCI blob does not match its descriptor")
        reg.upload_blob(content)
    reg.put_manifest(label, image["manifest"])
    _, headers, stored = reg.request(f"/v2/{REPOSITORY}/manifests/{image['digest']}", accept=OCI_MANIFEST)
    if stored != image["manifest"] or headers.get("Docker-Content-Digest") != image["digest"]:
        raise FixtureError("registry did not return the exact case-owned OCI image by digest")


def fetch_attestation(reg, approved, expected, artifact, envelope, ref):
    artifact_digest = digest(artifact)
    if ref.get("digest") != artifact_digest or ref.get("size") != len(artifact):
        raise FixtureError("referrers descriptor does not identify the published artifact")
    _, headers, downloaded_manifest = reg.request(
        f"/v2/{REPOSITORY}/manifests/{artifact_digest}", accept=OCI_MANIFEST,
    )
    if downloaded_manifest != artifact or headers.get("Docker-Content-Digest") != artifact_digest:
        raise FixtureError("fetched artifact manifest differs from the published bytes and digest")
    manifest = json.loads(downloaded_manifest)
    if manifest["subject"] != descriptor(OCI_MANIFEST, approved["manifest"]):
        raise FixtureError("artifact manifest does not identify the approved OCI image")
    layer, = manifest["layers"]
    _, _, downloaded = reg.request(f"/v2/{REPOSITORY}/blobs/{layer['digest']}",
                                   accept="application/octet-stream")
    if downloaded != envelope or layer != descriptor(ENVELOPE_TYPE, downloaded):
        raise FixtureError("retrieved SBOM envelope differs from the published bytes or descriptor")
    payload = verify_download(downloaded, expected, approved["digest"], reg.work)
    return artifact_digest, layer["digest"], json.loads(payload)["predicate"]


def verify(lab, work, approved, other, signed):
    work = work / "registry-attachment"
    work.mkdir(mode=0o700)
    reg = LocalRegistry(lab.context, work)
    try:
        reg.start()
        store_image(reg, "approved", approved)
        store_image(reg, "unrelated", other)
        before, discovery = referrers(reg, approved["digest"])
        other_before, other_baseline = referrers(reg, other["digest"])
        baseline = not before["manifests"] and not other_before["manifests"] and other_baseline == discovery
        lab.check("red", "Both exact registry image digests begin without discovered SBOM attachments",
                  baseline, {"approved_referrers": len(before["manifests"]),
                             "other_referrers": len(other_before["manifests"]),
                             "discovery": discovery})
        envelope = canonical({
            "payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(signed["payload"]).decode("ascii"),
            "signatures": [{"sig": base64.b64encode(signed["signature"]).decode("ascii")}],
        })
        artifact = attach(reg, approved["digest"], len(approved["manifest"]), envelope)
        listing, after_discovery = referrers(reg, approved["digest"])
        matches = [row for row in listing["manifests"] if row.get("artifactType") == ARTIFACT_TYPE]
        if after_discovery != discovery or len(matches) != 1:
            raise FixtureError("approved subject did not discover one signed-SBOM artifact through the same path")
        artifact_digest, envelope_digest, sbom = fetch_attestation(reg, approved, signed, artifact, envelope, matches[0])
        lab.check("green", "OCI discovery retrieves the identical signed SBOM accepted by the Kubernetes verifier",
                  sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.6",
                  {"subject_digest": approved["digest"], "approved_referrers": len(matches),
                   "envelope_bytes_and_signature_match": True, "sbom_format": "CycloneDX 1.6",
                   "discovery": discovery})
        after, other_discovery = referrers(reg, other["digest"])
        lab.check("positive", "The unrelated exact registry digest remains without the published attachment",
                  not after["manifests"] and other_discovery == discovery,
                  {"other_digest": other["digest"], "other_referrers": len(after["manifests"])})
    except FixtureError as error:
        lab.block(str(error))
    finally:
        reg.stop()
    report = {
        "attachment_discovery": discovery, "registry": REGISTRY_IMAGE, "registry_image_id": reg.image_id,
        "approved_digest": approved["digest"], "other_digest": other["digest"],
        "artifact_manifest_digest": artifact_digest, "signed_envelope_digest": envelope_digest,
        "registry_http_events": reg.events, "dsse_signature_verified": True,
        "registry_cleanup": "complete",
    }
    (lab.evidence / "registry-referrers.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    lab.check("positive", "Disposable OCI registry container and volume were removed",
              True, {"registry_cleanup": "complete"})
