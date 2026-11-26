#!/usr/bin/env python3
"""Exercise pinned local OCI registries with case-owned, synthetic artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


# Reuse the exact immutable image pins already used by neighboring SAF lab cases.
REGISTRY_IMAGE = "docker.io/library/registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
ZOT_IMAGE = "ghcr.io/project-zot/zot-minimal:v2.1.23@sha256:59cb5740832970818903c5ce104425762664c7880835ee566506aad397cd3458"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_CONFIG = "application/vnd.oci.empty.v1+json"
SUBJECT_REPO = "saf-case/retention-subject"
COPY_REPO = "saf-case/copied-subject"
KEEP_REPO = "saf-case/retained-control"
EMPTY = b"{}"
RUN_ID = "case-" + uuid.uuid4().hex[:10]


class FixtureError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


LOCAL_HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode()


def descriptor(media_type: str, raw: bytes) -> dict:
    return {"mediaType": media_type, "digest": digest(raw), "size": len(raw)}


def command(*args: str, check: bool = True, timeout: int = 120,
            input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    p = subprocess.run(args, input=input_bytes, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout, check=False)
    if check and p.returncode:
        raise FixtureError(f"command failed ({p.returncode}): {args[0]} {args[1:]}: "
                           f"{p.stderr.decode(errors='replace')[-1500:]}")
    return p


def retention_decision(item: dict, now_day: int) -> dict:
    """Evaluate synthetic inputs. Hold/retention obligations dominate budget pressure."""
    age = now_day - item["created_day"]
    reasons = []
    if item.get("legal_hold"):
        reasons.append("legal_hold")
    if now_day < item["retain_until_day"]:
        reasons.append("retention_period_active")
    if item.get("subject_retained"):
        reasons.append("subject_still_retained")
    eligible = not reasons and age >= item["minimum_age_days"]
    return {"id": item["id"], "age_days": age, "budget_exceeded": item["budget_exceeded"],
            "eligible": eligible, "reasons": reasons or (["minimum_age_not_met"]
            if age < item["minimum_age_days"] else ["eligible"]) }


def policy_inputs() -> list[dict]:
    common = {"created_day": 0, "minimum_age_days": 7, "retain_until_day": 30,
              "subject_retained": True, "budget_exceeded": True, "legal_hold": False}
    return [
        {**common, "id": "held-sbom", "legal_hold": True},
        {**common, "id": "young-signature", "created_day": 25, "minimum_age_days": 7},
        {**common, "id": "retained-attestation"},
        {**common, "id": "eligible-cohort-referrer", "retain_until_day": 0,
         "subject_retained": False, "legal_hold": False},
    ]


class LocalRegistry:
    def __init__(self, docker: list[str], name: str, image: str, root: Path,
                 config_path: Path | None = None):
        self.docker, self.name, self.image, self.root = docker, name, image, root
        self.config_path = config_path
        self.volume = name + "-data"
        self.port = 0
        self.base = ""
        self.events: list[dict] = []

    def start(self) -> None:
        command(*self.docker, "pull", self.image, timeout=300)
        repo_digests = json.loads(self.docker_run(
            "image", "inspect", "--format", "{{json .RepoDigests}}", self.image
        ).stdout)
        expected_digest = self.image.rsplit("@", 1)[1]
        if not any(value.endswith("@" + expected_digest) for value in repo_digests):
            raise FixtureError(f"could not confirm pinned registry image digest for {self.name}")
        self.docker_run("volume", "create", self.volume)
        args = ["run", "--detach", "--name", self.name, "--publish", "127.0.0.1::5000",
                "--mount", f"type=volume,src={self.volume},dst=/var/lib/registry"]
        if self.config_path:
            args += ["--mount", f"type=bind,src={self.config_path},dst=/etc/distribution/config.yml,readonly"]
        args += [self.image]
        self.docker_run(*args)
        self.wait_for_registry()

    def wait_for_registry(self) -> None:
        # Docker can allocate a different host port when a stopped registry restarts.
        text = self.docker_run("port", self.name, "5000/tcp").stdout.decode().strip()
        if not text.startswith("127.0.0.1:"):
            raise FixtureError("registry host port is not bound exclusively to loopback")
        self.port = int(text.rsplit(":", 1)[1])
        self.base = f"http://127.0.0.1:{self.port}"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                status, _, _ = self.request("/v2/", expected=(200,))
                if status == 200:
                    return
            except (OSError, FixtureError):
                time.sleep(0.25)
        logs = self.docker_run("logs", "--tail", "25", self.name, check=False)
        detail = (logs.stdout + logs.stderr).decode(errors="replace")
        raise FixtureError(f"{self.name} did not become ready: {detail[-3000:]}")

    def docker_run(self, *args: str, **kwargs) -> subprocess.CompletedProcess:
        return command(*self.docker, *args, **kwargs)

    def request(self, path: str, method: str = "GET", body: bytes | None = None,
                content_type: str | None = None, accept: str | None = None,
                expected=(200,)) -> tuple[int, object, bytes]:
        headers = {}
        if content_type: headers["Content-Type"] = content_type
        if accept: headers["Accept"] = accept
        req = urllib.request.Request(self.base + path, data=body, method=method, headers=headers)
        try:
            with LOCAL_HTTP.open(req, timeout=12) as r:
                status, hdr, data = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            status, hdr, data = e.code, e.headers, e.read()
        except urllib.error.URLError as e:
            raise FixtureError(f"{self.name} local registry request failed {method} {path}: {e}") from e
        if status not in expected:
            raise FixtureError(f"unexpected status {status}: {method} {path}")
        self.events.append({"method": method, "path": path, "status": status})
        return status, hdr, data

    def push_blob(self, repo: str, raw: bytes) -> dict:
        _, hdr, _ = self.request(f"/v2/{repo}/blobs/uploads/", "POST", b"", expected=(202,))
        loc = urllib.parse.urlsplit(urllib.parse.urljoin(self.base, hdr.get("Location", "")))
        if (loc.scheme != "http" or loc.hostname not in ("127.0.0.1", "localhost")
                or loc.port != self.port or not loc.path.startswith(f"/v2/{repo}/blobs/uploads/")):
            raise FixtureError("upload Location escaped local fixture repository")
        path = loc.path + ("?" + loc.query + "&" if loc.query else "?") + urllib.parse.urlencode({"digest": digest(raw)})
        self.request(path, "PUT", raw, "application/octet-stream", expected=(201,))
        return descriptor("application/octet-stream", raw)

    def read_blob(self, repo: str, blob_digest: str) -> bytes:
        _, _, raw = self.request(f"/v2/{repo}/blobs/{blob_digest}", expected=(200,))
        if digest(raw) != blob_digest:
            raise FixtureError("blob readback failed digest verification")
        return raw

    def put_manifest(self, repo: str, ref: str, raw: bytes) -> str:
        media_type = json.loads(raw).get("mediaType")
        if media_type not in (OCI_MANIFEST, OCI_INDEX):
            raise FixtureError("fixture only uploads OCI image manifests or indexes")
        _, hdr, _ = self.request(f"/v2/{repo}/manifests/{urllib.parse.quote(ref, safe=':')}",
                                 "PUT", raw, media_type, expected=(201,))
        observed = hdr.get("Docker-Content-Digest", digest(raw))
        if observed != digest(raw): raise FixtureError("registry returned a mismatched manifest digest")
        return observed

    def get_manifest(self, repo: str, ref: str, expected=(200,)) -> tuple[int, bytes]:
        status, _, raw = self.request(f"/v2/{repo}/manifests/{urllib.parse.quote(ref, safe=':')}",
                                      accept=f"{OCI_MANIFEST}, {OCI_INDEX}", expected=expected)
        if status == 200 and digest(raw) != ref and ref.startswith("sha256:"):
            raise FixtureError("manifest bytes do not match requested content digest")
        return status, raw

    def attach(self, repo: str, subject_digest: str, artifact_type: str,
               blob: bytes, fallback: bool) -> dict:
        layer = self.push_blob(repo, blob)
        config = self.push_blob(repo, EMPTY)
        doc = {"schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": artifact_type,
               "config": {**config, "mediaType": OCI_CONFIG}, "layers": [layer],
               "subject": {"mediaType": OCI_MANIFEST, "digest": subject_digest,
                           "size": self.subject_sizes[subject_digest]}}
        raw = canonical(doc)
        ref_digest = self.put_manifest(repo, "sha256:" + hashlib.sha256(raw).hexdigest(), raw)
        entry = {"mediaType": OCI_MANIFEST, "digest": ref_digest, "size": len(raw),
                 "artifactType": artifact_type}
        if fallback:
            tag = referrers_tag(subject_digest)
            try:
                _, old = self.get_manifest(repo, tag)
                index = json.loads(old)
                if index.get("mediaType") != OCI_INDEX:
                    raise FixtureError("fallback tag does not contain an OCI index")
            except FixtureError as e:
                if "status 404" not in str(e): raise
                index = {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": []}
            entries = index.setdefault("manifests", [])
            if not any(x.get("digest") == ref_digest for x in entries): entries.append(entry)
            self.put_manifest(repo, tag, canonical(index))
        return {"digest": ref_digest, "manifest": doc, "blob": blob, "entry": entry}

    def discover(self, repo: str, subject_digest: str, allow_fallback: bool) -> tuple[str, list[dict]]:
        status, _, raw = self.request(f"/v2/{repo}/referrers/{subject_digest}",
                                      accept=OCI_INDEX, expected=(200, 404))
        if status == 200:
            index = json.loads(raw)
            if index.get("mediaType") != OCI_INDEX: raise FixtureError("native response is not OCI index")
            return "native-referrers-api", index.get("manifests", [])
        if not allow_fallback: raise FixtureError("native Referrers API returned 404 unexpectedly")
        tag = referrers_tag(subject_digest)
        status, raw = self.get_manifest(repo, tag, expected=(200, 404))
        if status == 404: return "referrers-tag-fallback", []
        index = json.loads(raw)
        if index.get("mediaType") != OCI_INDEX:
            raise FixtureError("fallback tag does not contain an OCI index")
        return "referrers-tag-fallback", index.get("manifests", [])

    def remove_fallback_entry(self, repo: str, subject_digest: str, referrer_digest: str) -> None:
        tag = referrers_tag(subject_digest)
        _, raw = self.get_manifest(repo, tag)
        index = json.loads(raw)
        rows = index.get("manifests", [])
        index["manifests"] = [row for row in rows if row.get("digest") != referrer_digest]
        self.put_manifest(repo, tag, canonical(index))

    def stop(self) -> None:
        self.docker_run("rm", "--force", self.name, check=False)
        self.docker_run("volume", "rm", self.volume, check=False)
        if self.docker_run("inspect", self.name, check=False).returncode == 0:
            raise FixtureError("fixture registry container remains after cleanup")
        if self.docker_run("volume", "inspect", self.volume, check=False).returncode == 0:
            raise FixtureError("fixture registry volume remains after cleanup")


def referrers_tag(subject_digest: str) -> str:
    algorithm, encoded = subject_digest.split(":", 1)
    return algorithm[:32] + "-" + encoded[:64]


def openssl_binary():
    candidates = (shutil.which("openssl"), "/opt/homebrew/opt/openssl@3/bin/openssl",
                  "/usr/local/opt/openssl@3/bin/openssl")
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            version = command(candidate, "version", check=False)
            if version.returncode == 0 and version.stdout.startswith(b"OpenSSL 3."):
                return candidate
    raise FixtureError("OpenSSL 3 with Ed25519 support is required for this case")


def fixture_material(work: Path, openssl: str) -> tuple[bytes, list[tuple[str, bytes]]]:
    # Every identity and payload is created in this run's private temporary directory.
    key, pub = work / "fixture.key", work / "fixture.pub"
    command(openssl, "genpkey", "-algorithm", "ED25519", "-out", str(key))
    command(openssl, "pkey", "-in", str(key), "-pubout", "-out", str(pub))
    cfg = canonical({"architecture": "amd64", "os": "linux", "config": {}, "rootfs": {"type": "layers", "diff_ids": []}})
    subject = {"schemaVersion": 2, "mediaType": OCI_MANIFEST,
               "config": descriptor("application/vnd.oci.image.config.v1+json", cfg), "layers": []}
    # DSSE PAE signed with an ephemeral Ed25519 private key. The key is deleted at teardown.
    subject_digest = digest(canonical(subject))
    statement = {"_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": "case-owned-subject", "digest": {"sha256": subject_digest.removeprefix("sha256:")}}],
                "predicateType": "https://slsa.dev/provenance/v1", "predicate": {"buildType": "saf.fixture/only"}}
    payload = canonical(statement)
    ptype = "application/vnd.in-toto+json"
    pae = b"DSSEv1 " + str(len(ptype)).encode() + b" " + ptype.encode() + b" " + str(len(payload)).encode() + b" " + payload
    pae_file, sig_file = work / "payload.pae", work / "signature.bin"
    pae_file.write_bytes(pae)
    command(openssl, "pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(pae_file), "-out", str(sig_file))
    envelope = canonical({"payloadType": ptype, "payload": base64.b64encode(payload).decode(),
                          "signatures": [{"keyid": "ephemeral-case-key", "sig": base64.b64encode(sig_file.read_bytes()).decode()}]})
    sbom = canonical({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                      "metadata": {"component": {"type": "application", "name": "case-only", "version": RUN_ID}}, "components": []})
    return canonical(subject), [
        ("application/vnd.dsse.envelope.v1+json", envelope),
        ("application/vnd.in-toto+json", payload),
        ("application/vnd.cyclonedx+json", sbom),
    ]


def assert_artifact_set(reg: LocalRegistry, repo: str, subject: dict, artifacts: list[dict], fallback: bool) -> None:
    mode, rows = reg.discover(repo, subject["digest"], allow_fallback=fallback)
    got = {row["digest"] for row in rows}
    expected = {a["digest"] for a in artifacts}
    if got != expected: raise FixtureError(f"{mode}: expected referrers {expected}, observed {got}")
    _, manifest = reg.get_manifest(repo, subject["digest"])
    if digest(manifest) != subject["digest"]: raise FixtureError("subject readback digest mismatch")
    for a in artifacts:
        _, raw = reg.get_manifest(repo, a["digest"])
        doc = json.loads(raw)
        if digest(raw) != a["digest"] or doc.get("subject", {}).get("digest") != subject["digest"]:
            raise FixtureError("referrer readback lost exact OCI subject relationship")
        if reg.read_blob(repo, doc["layers"][0]["digest"]) != a["blob"]:
            raise FixtureError("referrer payload bytes differ from the case-owned fixture")


def apply_zot_native_retention(reg: LocalRegistry, repo: str, subject_digest: str,
                               artifacts: list[dict], decision: dict) -> list[str]:
    """Bounded controller path: discover exact links, preserve or retire cohort."""
    mode, rows = reg.discover(repo, subject_digest, False)
    expected = {item["digest"] for item in artifacts}
    if mode != "native-referrers-api" or {row["digest"] for row in rows} != expected:
        raise FixtureError("Zot retention precondition did not find the exact native cohort")
    # Re-read every descriptor before using the policy decision to authorize deletion.
    for item in artifacts:
        _, raw = reg.get_manifest(repo, item["digest"])
        doc = json.loads(raw)
        if (digest(raw) != item["digest"] or doc.get("subject", {}).get("digest") != subject_digest
                or reg.read_blob(repo, doc["layers"][0]["digest"]) != item["blob"]):
            raise FixtureError("Zot retention precondition lost a referrer digest or subject link")
    _, subject_raw = reg.get_manifest(repo, subject_digest)
    if digest(subject_raw) != subject_digest:
        raise FixtureError("Zot retention precondition lost the subject bytes")
    if not decision["eligible"]:
        return []
    deleted = []
    for item in artifacts:
        reg.request(f"/v2/{repo}/manifests/{item['digest']}", "DELETE", expected=(202,))
        deleted.append(item["digest"])
    reg.request(f"/v2/{repo}/manifests/{subject_digest}", "DELETE", expected=(202,))
    deleted.append(subject_digest)
    return deleted


def zot_native_cohort_lifecycle(zot: LocalRegistry, subject_raw: bytes, subject_config: bytes,
                                materials: list[tuple[str, bytes]],
                                openssl: str, work: Path) -> dict:
    """Apply the bounded policy decision to actual Zot-native OCI cohorts."""
    subject_digest = digest(subject_raw)
    subject_size = len(subject_raw)
    if digest(subject_config) != json.loads(subject_raw)["config"]["digest"]:
        raise FixtureError("the case-owned subject configuration does not match its manifest")
    zot.subject_sizes[subject_digest] = subject_size
    day = 31
    specs = {
        "held": {"created_day": 0, "minimum_age_days": 7, "retain_until_day": 30,
                 "subject_retained": False, "budget_exceeded": True, "legal_hold": True},
        "retention-active": {"created_day": 0, "minimum_age_days": 7, "retain_until_day": 60,
                             "subject_retained": False, "budget_exceeded": True, "legal_hold": False},
        "expired": {"created_day": 0, "minimum_age_days": 7, "retain_until_day": 30,
                    "subject_retained": False, "budget_exceeded": True, "legal_hold": False},
    }
    seeded = {}
    for cohort, fields in specs.items():
        repo = f"saf-case/zot-retention/{RUN_ID}/{cohort}"
        zot.push_blob(repo, subject_config)
        zot.put_manifest(repo, subject_digest, subject_raw)
        artifacts = [zot.attach(repo, subject_digest, artifact_type, blob, False)
                     for artifact_type, blob in materials]
        assert_artifact_set(zot, repo, {"digest": subject_digest}, artifacts, False)
        seeded[cohort] = {"repo": repo, "subject": subject_digest, "artifacts": artifacts,
                          "decision": retention_decision({"id": cohort, **fields}, day)}

    protected_results = {}
    for cohort in ("held", "retention-active"):
        item = seeded[cohort]
        before = len(zot.events)
        deleted = apply_zot_native_retention(zot, item["repo"], item["subject"],
                                             item["artifacts"], item["decision"])
        # The controller path performs no DELETE for a protected decision.
        if item["decision"]["eligible"]:
            raise FixtureError(f"protected Zot cohort unexpectedly eligible: {cohort}")
        protected_results[cohort] = {
            "ineligible": not item["decision"]["eligible"],
            "delete_requests": [event for event in zot.events[before:] if event["method"] == "DELETE"],
            "controller_deleted": deleted,
        }
        assert_artifact_set(zot, item["repo"], {"digest": item["subject"]}, item["artifacts"], False)
        protected_results[cohort]["still_discoverable"] = True

    expired = seeded["expired"]
    if not expired["decision"]["eligible"]:
        raise FixtureError("expired Zot cohort did not meet the synthetic retention policy")
    expected_refs = {artifact["digest"] for artifact in expired["artifacts"]}
    deleted = apply_zot_native_retention(zot, expired["repo"], expired["subject"],
                                         expired["artifacts"], expired["decision"])
    if sorted(deleted[:-1]) != sorted(expected_refs) or deleted[-1] != expired["subject"]:
        raise FixtureError("eligible cohort did not retire referrers before its subject")
    missing = [zot.get_manifest(expired["repo"], digest_value, expected=(404,))[0] == 404
               for digest_value in [expired["subject"]] + sorted(expected_refs)]
    status, _, raw_index = zot.request(f"/v2/{expired['repo']}/referrers/{expired['subject']}",
                                       accept=OCI_INDEX, expected=(200, 404))
    index_empty = status == 404 or json.loads(raw_index).get("manifests", []) == []
    if not all(missing) or not index_empty:
        raise FixtureError("Zot did not remove the exact eligible cohort from manifests and discovery")

    # Restore the same inert subject/referrers from the in-memory case fixture,
    # then require identical descriptors, payloads and DSSE subject signature.
    zot.push_blob(expired["repo"], subject_config)
    zot.put_manifest(expired["repo"], expired["subject"], subject_raw)
    restored = [zot.attach(expired["repo"], expired["subject"], artifact_type, blob, False)
                for artifact_type, blob in materials]
    assert_artifact_set(zot, expired["repo"], {"digest": expired["subject"]}, restored, False)
    restored_refs = {artifact["digest"] for artifact in restored}
    if restored_refs != expected_refs:
        raise FixtureError("re-push recovery changed a referrer manifest digest")
    envelope = json.loads(zot.read_blob(expired["repo"], restored[0]["manifest"]["layers"][0]["digest"]))
    payload = base64.b64decode(envelope["payload"], validate=True)
    payload_type = envelope["payloadType"]
    pae = (b"DSSEv1 " + str(len(payload_type)).encode() + b" " + payload_type.encode() + b" "
           + str(len(payload)).encode() + b" " + payload)
    pae_path, signature_path = work / "zot-recovered.pae", work / "zot-recovered.sig"
    pae_path.write_bytes(pae)
    signature_path.write_bytes(base64.b64decode(envelope["signatures"][0]["sig"], validate=True))
    command(openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(work / "fixture.pub"),
            "-rawin", "-in", str(pae_path), "-sigfile", str(signature_path))
    statement = json.loads(payload)
    statement_subject = statement.get("subject", [{}])[0].get("digest", {}).get("sha256")
    signature_binds_subject = (statement_subject == expired["subject"].removeprefix("sha256:"))
    if not signature_binds_subject:
        raise FixtureError("recovered Zot DSSE statement no longer binds to the exact subject")
    return {"protected_cohorts": protected_results,
            "expired_cohort": {"decision_eligible": True, "initial_native_referrers": len(expected_refs),
                               "deleted_referrers_then_subject": deleted,
                               "all_manifests_absent_after_retirement": all(missing),
                               "native_discovery_empty_after_retirement": index_empty,
                               "re_pushed_subject_digest_unchanged": digest(subject_raw) == expired["subject"],
                               "re_pushed_referrer_digests_unchanged": restored_refs == expected_refs,
                               "restored_payload_signature_verified": True,
                               "restored_statement_binds_subject": signature_binds_subject}}


def run_fixture(context: str, workspace: Path) -> dict:
    openssl = openssl_binary()
    ctx = json.loads(command("docker", "context", "inspect", context).stdout)
    host = ctx[0].get("Endpoints", {}).get("docker", {}).get("Host", "")
    if not host.startswith("unix://"):
        raise FixtureError("only a local Unix-socket Docker context is allowed")
    docker_cfg = Path(tempfile.mkdtemp(prefix=".docker-config-", dir=workspace))
    docker = ["env", "-u", "DOCKER_CONTEXT", "-u", "DOCKER_HOST", "docker", "--config", str(docker_cfg), "--host", host]
    work = Path(tempfile.mkdtemp(prefix=".run-", dir=workspace))
    cfg = work / "registry.yml"
    cfg.write_text("version: 0.1\nstorage:\n  filesystem:\n    rootdirectory: /var/lib/registry\n"
                   "  delete:\n    enabled: true\nhttp:\n  addr: :5000\n  relativeurls: true\n"
                   "log:\n  level: info\n", encoding="utf-8")
    dist = LocalRegistry(docker, RUN_ID + "-distribution", REGISTRY_IMAGE, work, cfg)
    zot = LocalRegistry(docker, RUN_ID + "-zot", ZOT_IMAGE, work)
    report = {"run_id": RUN_ID, "scope": "case-owned OCI content on loopback-only disposable registries",
              "policy_inputs": [], "registries": {}}
    started = []
    try:
        started.append(dist); dist.start()
        started.append(zot); zot.start()
        print('Both pinned loopback registries are ready.', flush=True)
        subject_raw, materials = fixture_material(work, openssl)
        # upload config, then tag the immutable subject by digest and a case-owned tag
        c = canonical({"architecture": "amd64", "os": "linux", "config": {}, "rootfs": {"type": "layers", "diff_ids": []}})
        dist.push_blob(SUBJECT_REPO, c); zot.push_blob(SUBJECT_REPO, c)
        sdist = dist.put_manifest(SUBJECT_REPO, "retained-" + RUN_ID, subject_raw)
        szot = zot.put_manifest(SUBJECT_REPO, "retained-" + RUN_ID, subject_raw)
        dist.subject_sizes, zot.subject_sizes = {sdist: len(subject_raw)}, {szot: len(subject_raw)}
        created = {}
        for reg, sub, fallback in ((dist, sdist, True), (zot, szot, False)):
            artifacts = [reg.attach(SUBJECT_REPO, sub, typ, blob, fallback) for typ, blob in materials]
            assert_artifact_set(reg, SUBJECT_REPO, {"digest": sub}, artifacts, fallback)
            mode, _ = reg.discover(SUBJECT_REPO, sub, fallback)
            created[reg.name] = artifacts
            report["registries"][reg.name] = {"discovery": mode, "initial_referrers": len(artifacts), "subject_digest": sub}
        # Verify the DSSE signature over the exact envelope payload after registry readback.
        dsse_record = created[dist.name][0]
        dsse = dist.read_blob(SUBJECT_REPO, dsse_record["manifest"]["layers"][0]["digest"])
        envelope = json.loads(dsse)
        signed_payload = base64.b64decode(envelope["payload"], validate=True)
        ptype = envelope["payloadType"]
        pae = b"DSSEv1 " + str(len(ptype)).encode() + b" " + ptype.encode() + b" " + str(len(signed_payload)).encode() + b" " + signed_payload
        (work / "verify.pae").write_bytes(pae)
        (work / "verify.sig").write_bytes(base64.b64decode(envelope["signatures"][0]["sig"], validate=True))
        verify = (openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(work / "fixture.pub"),
                  "-rawin", "-in", str(work / "verify.pae"), "-sigfile", str(work / "verify.sig"))
        command(*verify)
        (work / "verify.pae").write_bytes(pae[:-1] + b"!")
        if command(*verify, check=False).returncode == 0:
            raise FixtureError("modified DSSE payload passed signature validation")
        statement = json.loads(signed_payload)
        if statement.get("_type") != "https://in-toto.io/Statement/v1" or statement.get("predicateType") != "https://slsa.dev/provenance/v1":
            raise FixtureError("attestation statement did not pass schema identity checks")
        statement_subject = statement["subject"][0]["digest"]["sha256"]
        if statement_subject != sdist.removeprefix("sha256:"):
            raise FixtureError("signed attestation subject digest does not equal the registry subject")
        report["cryptographic_fixture"] = {"dsse_signature_verified": True, "altered_payload_rejected": True,
            "attestation_subject_digest": "sha256:" + statement_subject,
            "sbom_payload_digest": digest(created[dist.name][2]["blob"])}

        # Copy the subject and its metadata to a distinct repository, preserving digests and links.
        copied_subjects = []
        for reg, artifacts, fallback in ((dist, created[dist.name], True), (zot, created[zot.name], False)):
            reg.push_blob(COPY_REPO, c)
            copy_digest = reg.put_manifest(COPY_REPO, "copied-" + RUN_ID, subject_raw)
            reg.subject_sizes[copy_digest] = len(subject_raw)
            copied = []
            for original in artifacts:
                blob = original["blob"]
                copied.append(reg.attach(COPY_REPO, copy_digest, original["manifest"]["artifactType"], blob, fallback))
            assert_artifact_set(reg, COPY_REPO, {"digest": copy_digest}, copied, fallback)
            digest_stable = (copy_digest == digest(subject_raw)
                             and {entry["digest"] for entry in copied} == {entry["digest"] for entry in artifacts})
            if not digest_stable:
                raise FixtureError("repository copy changed the immutable subject or referrer digests")
            copied_subjects.append({"registry": reg.name, "digests_stable": True, "referrers": len(copied)})
        report["deliberate_copy"] = copied_subjects

        print('Registry discovery, payload verification, and copy checks passed.', flush=True)
        # A red baseline removes one metadata manifest while its subject is retained.
        baseline = created[dist.name][2]
        dist.request(f"/v2/{SUBJECT_REPO}/manifests/{baseline['digest']}", "DELETE", expected=(202,))
        dist.remove_fallback_entry(SUBJECT_REPO, sdist, baseline["digest"])
        mode, rows = dist.discover(SUBJECT_REPO, sdist, True)
        if any(row["digest"] == baseline["digest"] for row in rows):
            raise FixtureError("early-deletion baseline did not produce observable metadata loss")
        _, still_subject = dist.get_manifest(SUBJECT_REPO, sdist)
        if digest(still_subject) != sdist: raise FixtureError("baseline unexpectedly lost its subject")
        report["red_baseline"] = {"early_loss_observed": True, "subject_remained": True, "discovery": mode}

        # Restore via a deliberate push; guarded policy denies budget-driven deletion while held/retained.
        restored = dist.attach(SUBJECT_REPO, sdist, baseline["manifest"]["artifactType"], baseline["blob"], True)
        remaining = [created[dist.name][0], created[dist.name][1], restored]
        assert_artifact_set(dist, SUBJECT_REPO, {"digest": sdist}, remaining, True)
        decisions = [retention_decision(x, 31) for x in policy_inputs()]
        if any(x["eligible"] for x in decisions[:3]) or not decisions[3]["eligible"]:
            raise FixtureError("synthetic policy oracle failed hold, age, budget, or eligible-cohort cases")
        report["policy_inputs"] = decisions
        report["guarded_retention"] = {"all_referrers_available": True, "budget_override_denied_for_held_or_retained": True}

        # Eligible cleanup: remove all copied/source descriptors and referrer-index tag, then real Distribution GC.
        # The fallback index is identified from its tag, read back, and deleted by digest.
        keeper_blob = b"retained fixture payload"
        dist.push_blob(KEEP_REPO, c)
        keeper_subject = dist.put_manifest(KEEP_REPO, "keeper-" + RUN_ID, subject_raw)
        keeper = dist.attach(KEEP_REPO, keeper_subject, "application/vnd.saf.fixture.retained", keeper_blob, True)
        assert_artifact_set(dist, KEEP_REPO, {"digest": keeper_subject}, [keeper], True)
        gc_blob_checks = []
        for repo, sub, artifacts in ((SUBJECT_REPO, sdist, remaining), (COPY_REPO, sdist, created[dist.name])):
            # The copy has identical subject bytes/digest; each repository has independent links.
            for a in artifacts:
                dist.request(f"/v2/{repo}/manifests/{a['digest']}", "DELETE", expected=(202,))
            tag = referrers_tag(sub)
            status, index_raw = dist.get_manifest(repo, tag, expected=(200, 404))
            if status == 200:
                dist.request(f"/v2/{repo}/manifests/{digest(index_raw)}", "DELETE", expected=(202,))
            # subject removal is intentionally last in the cohort
            dist.request(f"/v2/{repo}/manifests/{sub}", "DELETE", expected=(202,))
            for d in [sub] + [a["digest"] for a in artifacts]:
                dist.get_manifest(repo, d, expected=(404,))
            dist.get_manifest(repo, tag, expected=(404,))
            for a in artifacts:
                layer_digest = a["manifest"]["layers"][0]["digest"]
                # Deleting a manifest unlinks it; its blob may remain until the real sweep.
                dist.request(f"/v2/{repo}/blobs/{layer_digest}", expected=(200,))
                gc_blob_checks.append((repo, layer_digest))
        print('Eligible manifest links are absent and unreferenced content is still present before GC.', flush=True)
        # Stop service, run Distribution GC with the exact same mounted storage and config, restart.
        dist.docker_run("stop", dist.name)
        dist.docker_run("run", "--rm", "--name", RUN_ID + "-gc",
                        "--mount", f"type=volume,src={dist.volume},dst=/var/lib/registry",
                        "--mount", f"type=bind,src={cfg},dst=/etc/distribution/config.yml,readonly",
                        REGISTRY_IMAGE, "garbage-collect", "/etc/distribution/config.yml")
        print('Distribution GC completed on stopped registry storage.', flush=True)
        dist.docker_run("start", dist.name)
        dist.wait_for_registry()
        for repo, sub, artifacts in ((SUBJECT_REPO, sdist, remaining), (COPY_REPO, sdist, created[dist.name])):
            dist.get_manifest(repo, sub, expected=(404,))
            for a in artifacts: dist.get_manifest(repo, a["digest"], expected=(404,))
            dist.get_manifest(repo, referrers_tag(sub), expected=(404,))
        for repo, blob_digest in gc_blob_checks:
            dist.request(f"/v2/{repo}/blobs/{blob_digest}", expected=(404,))
        assert_artifact_set(dist, KEEP_REPO, {"digest": keeper_subject}, [keeper], True)
        report["eligible_cleanup_and_gc"] = {"retained_payload_survived_gc": True,
            "manifests_absent_before_gc": True,
            "fallback_indexes_absent_before_gc": True, "distribution_gc_completed": True,
            "manifests_and_indexes_absent_after_gc": True, "unreferenced_payload_blobs_absent_after_gc": True}
        report["zot_native_lifecycle"] = zot_native_cohort_lifecycle(zot, subject_raw, c, materials,
                                                                       openssl, work)
        report["limitations"] = [
            "Distribution 3.0.0 is tested through an actual Referrers API request and its OCI tag-schema fallback; API 404 is expected for this pinned release/harness.",
            "Zot native API behavior is observed only for this pinned local fixture; no native registry GC claim is made.",
            "Synthetic age, budget, retention-until and legal-hold booleans are policy inputs, not a live scheduler, registry retention engine or legal authority.",
            "The ephemeral DSSE signature is cryptographically generated but this fixture does not verify a production identity or trust policy.",
            "Copy is deliberate within each disposable registry across two repositories; it does not establish fleet replication or provider-specific copy semantics.",
            "Distribution GC tests its filesystem-backed disposable volume after explicit manifest deletions; it does not prove managed registry GC behavior or recoverability.",
            "Zot retention recovery re-pushes only the same in-memory synthetic manifest and payload bytes; it is not a backup/restore or Zot storage-GC proof.",
        ]
        report["external_tracking"] = ["organization retention schedule", "registry fleet and provider inventory",
                                        "authorized legal-hold source and release authority", "production recovery evidence"]
        report["request_log"] = {dist.name: dist.events, zot.name: zot.events}
        return report
    finally:
        cleanup_errors = []
        for reg in reversed(started):
            try:
                reg.stop()
            except Exception as error:  # attempt cleanup of every owned resource
                cleanup_errors.append(str(error))
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(docker_cfg, ignore_errors=True)
        if cleanup_errors:
            raise FixtureError("cleanup incomplete: " + "; ".join(cleanup_errors))



def run_registry_evidence(lab):
    try:
        report = run_fixture(lab.context, lab.kubeconfig.parent)
    except FixtureError as error:
        lab.block(str(error))
    (lab.evidence / "oci-co-retention.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    modes = sorted(item["discovery"] for item in report["registries"].values())
    lab.check("positive", "The pinned Zot and Distribution fixtures return native and fallback OCI discovery",
              modes == ["native-referrers-api", "referrers-tag-fallback"], {"discovery": modes})
    crypto = report["cryptographic_fixture"]
    lab.check("green", "Registry readback verifies the DSSE signature and binds the statement to the subject",
              crypto["dsse_signature_verified"] and crypto["altered_payload_rejected"],
              {"signature_verified": crypto["dsse_signature_verified"], "modified_payload_rejected": crypto["altered_payload_rejected"]})
    copies = report["deliberate_copy"]
    stable_copy = len(copies) == 2 and all(item["digests_stable"] and item["referrers"] == 3 for item in copies)
    lab.check("positive", "Both case registries preserve subject and all referrer digests in a separate repository",
              stable_copy, {"digest_preserving_copies": stable_copy, "associated_artifact_types": 3})
    missed = report["red_baseline"]
    lab.check("red", "Deleting one referrer prematurely removes it from discovery while the subject stays readable",
              missed["early_loss_observed"] and missed["subject_remained"],
              {"referrer_lost": missed["early_loss_observed"], "subject_readable": missed["subject_remained"]})
    reclaimed = report["eligible_cleanup_and_gc"]
    lab.check("green", "Distribution GC removes unreferenced payload bytes and preserves the retained cohort",
              all(reclaimed.values()), reclaimed)
    zot_lifecycle = report["zot_native_lifecycle"]
    protected = zot_lifecycle["protected_cohorts"]
    expired = zot_lifecycle["expired_cohort"]
    safe_zot = (all(row["ineligible"] and not row["delete_requests"]
                    and not row["controller_deleted"] and row["still_discoverable"]
                    for row in protected.values())
                and expired["decision_eligible"]
                and expired["all_manifests_absent_after_retirement"]
                and expired["native_discovery_empty_after_retirement"]
                and expired["re_pushed_subject_digest_unchanged"]
                and expired["re_pushed_referrer_digests_unchanged"]
                and expired["restored_payload_signature_verified"]
                and expired["restored_statement_binds_subject"])
    observation = {key: value for key, value in expired.items()
                   if key != "deleted_referrers_then_subject"}
    observation.update(
        protected_cohorts_unchanged=all(
            row["still_discoverable"] and not row["delete_requests"] for row in protected.values()),
        completed_ordered_manifest_deletions=len(expired["deleted_referrers_then_subject"]),
    )
    lab.check("positive", "Zot native retention preserves protected cohorts and re-push restores an eligible cohort",
              safe_zot, observation)
