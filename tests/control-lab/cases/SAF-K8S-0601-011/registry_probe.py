"""Exercise actual referrer availability in a loopback-only disposable registry."""
import hashlib
import http.client
import json
import time
from urllib.parse import urlsplit


REGISTRY = (
    "docker.io/library/registry:3.0.0@sha256:"
    "6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
INDEX = "application/vnd.oci.image.index.v1+json"
EMPTY_BYTES = b"{}"
CATEGORIES = ("signature", "attestation", "sbom")
SUBJECT_KEEP_UNTIL = 10


def serialized(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class Registry:
    def __init__(self, lab, port, repo):
        self.lab = lab
        self.port = port
        self.prefix = f"/v2/{repo}"
        self.fallback_index = None

    def request(self, method, suffix, body=None, headers=None, expected=(200,)):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=6)
        try:
            conn.request(method, self.prefix + suffix, body=body, headers=headers or {})
            result = conn.getresponse()
            payload = result.read()
            if result.status not in expected:
                self.lab.block(f"Disposable registry {method} {suffix} returned {result.status}")
            return result.status, dict(result.getheaders()), payload
        finally:
            conn.close()

    def seed_blob(self):
        _, response, _ = self.request("POST", "/blobs/uploads/", expected=(202,))
        location = response.get("Location", "")
        # A Docker registry emits an absolute or relative URL. Reuse only the
        # upload path and query on this explicitly local connection.
        upload = urlsplit(location)
        if not upload.path.startswith(self.prefix + "/blobs/uploads/"):
            self.lab.block("Registry upload location left the owned repository")
        query = upload.query + ("&" if upload.query else "") + "digest=" + digest(EMPTY_BYTES)
        self.request("PUT", upload.path.removeprefix(self.prefix) + "?" + query,
                     EMPTY_BYTES, {"Content-Type": "application/octet-stream"}, expected=(201,))

    def manifest(self, tag, kind, subject=None):
        content = {
            "schemaVersion": 2, "mediaType": MANIFEST,
            "artifactType": f"application/vnd.saf.fixture.{kind}",
            "config": {"mediaType": "application/vnd.oci.empty.v1+json",
                       "digest": digest(EMPTY_BYTES), "size": len(EMPTY_BYTES)},
            "layers": [],
        }
        if subject:
            content["subject"] = subject
        raw = serialized(content)
        _, headers, _ = self.request("PUT", f"/manifests/{tag}", raw,
                                      {"Content-Type": MANIFEST}, expected=(201,))
        output = {"mediaType": MANIFEST, "digest": digest(raw), "size": len(raw),
                  "artifactType": content["artifactType"]}
        if headers.get("Docker-Content-Digest") != output["digest"]:
            self.lab.block("Registry stored a different manifest digest")
        return output

    def advertised(self, subject, refs):
        status, _, payload = self.request("GET", f"/referrers/{subject['digest']}",
                                          headers={"Accept": INDEX}, expected=(200, 404))
        method = "referrers-api"
        if status == 404:
            method = "fallback-tag"
            tag = subject["digest"].replace(":", "-", 1)
            raw = serialized({"schemaVersion": 2, "mediaType": INDEX, "manifests": refs})
            self.request("PUT", f"/manifests/{tag}", raw, {"Content-Type": INDEX}, expected=(201,))
            self.fallback_index = {"digest": digest(raw), "mediaType": INDEX}
            _, _, payload = self.request("GET", f"/manifests/{tag}", headers={"Accept": INDEX})
        actual = {row["digest"] for row in json.loads(payload)["manifests"]}
        return actual == {row["digest"] for row in refs}, method

    def available(self, row):
        status, _, _ = self.request("HEAD", f"/manifests/{row['digest']}",
                                     headers={"Accept": row["mediaType"]}, expected=(200, 404))
        return status == 200

    def delete(self, row):
        self.request("DELETE", f"/manifests/{row['digest']}", expected=(202,))


def wait_for_registry(lab, name):
    deadline = time.monotonic() + 30
    lines = lab.command("docker", "port", name, "5000/tcp").stdout.strip().splitlines()
    if len(lines) != 1 or not lines[0].startswith("127.0.0.1:"):
        lab.block("Disposable registry must be bound exclusively to IPv4 loopback")
    port = int(lines[0].split(":")[1])
    while time.monotonic() < deadline:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            conn.request("GET", "/v2/")
            if conn.getresponse().status == 200:
                return port
        except (OSError, http.client.HTTPException):
            pass
        finally:
            conn.close()
        time.sleep(0.3)
    lab.block("Loopback-only fixture registry did not become ready")


def seed(registry):
    registry.seed_blob()
    target = registry.manifest("subject", "subject")
    return target, [registry.manifest(kind, kind, target) for kind in CATEGORIES]


def apply_retention(registry, subject, refs, evaluation_time):
    if evaluation_time < SUBJECT_KEEP_UNTIL:
        return False
    for entry in refs:
        registry.delete(entry)
    if registry.fallback_index is not None:
        registry.delete(registry.fallback_index)
    registry.delete(subject)
    return True


def run_registry(lab):
    name = f"saf-registry-{lab.cluster}"
    existing = lab.command("docker", "container", "inspect", name, allow_failure=True)
    if existing.returncode == 0:
        lab.block("Fixture registry name is already used")
    lab.command("docker", "run", "--rm", "-d", "--name", name,
                "-p", "127.0.0.1::5000", "-e", "REGISTRY_STORAGE_DELETE_ENABLED=true",
                REGISTRY, timeout=90)
    try:
        port = wait_for_registry(lab, name)
        unmanaged = Registry(lab, port, "saf/referrer-baseline")
        original, original_refs = seed(unmanaged)
        before, discovery = unmanaged.advertised(original, original_refs)
        unmanaged.delete(original_refs[0])
        orphan = unmanaged.available(original) and not unmanaged.available(original_refs[0])
        lab.check("red", "The registry alone allows a linked referrer to disappear while its subject remains",
                  before and orphan, {"original_set_advertised": before, "discovery": discovery, "early_loss_observed": orphan})

        governed = Registry(lab, port, "saf/referrer-governed")
        subject, refs = seed(governed)
        complete, discovery = governed.advertised(subject, refs)
        removed_early = apply_retention(governed, subject, refs, SUBJECT_KEEP_UNTIL - 1)
        kept = governed.available(subject) and all(governed.available(entry) for entry in refs)
        lab.check("green", "A retention guard preserves the available subject and all three associated referrers",
                  complete and not removed_early and kept,
                  {"exact_referrer_set_advertised": complete, "discovery": discovery,
                   "early_retirement_denied": not removed_early,
                   "subject_and_all_referrers_available": kept})
        retired = apply_retention(governed, subject, refs, SUBJECT_KEEP_UNTIL)
        absent = not governed.available(subject) and all(not governed.available(entry) for entry in refs)
        index_absent = governed.fallback_index is None or not governed.available(governed.fallback_index)
        lab.check("positive", "Eligible retirement removes the fixture subject, linked manifests and fallback index",
                  retired and absent and index_absent,
                  {"eligible_retirement_permitted": retired, "all_manifests_absent": absent,
                   "fallback_index_absent": index_absent})
    finally:
        lab.command("docker", "rm", "-f", name)
