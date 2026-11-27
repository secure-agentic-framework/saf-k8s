"""Bounded application-layer AEAD proof on one case-owned Kubernetes PVC."""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import subprocess
import tempfile
import time


NAMESPACE = "saf-test"
CONTROL_ID = "SAF-K8S-0901-003"
IMAGE_PREFIX = "saf-0901-003-pvc-aead:cryptography-50.0.2-"
PVC = "saf-0901-003-aead-pvc"
KEY_SECRET = "saf-0901-003-aead-key"
CODE_CONFIG = "saf-0901-003-aead-code"
JOB = {
    "write": "saf-0901-003-aead-write",
    "observe": "saf-0901-003-aead-observe",
    "tamper": "saf-0901-003-aead-tamper-copy",
    "restore": "saf-0901-003-aead-restore",
    "reject": "saf-0901-003-aead-reject-tampered",
}
MAGIC = b"SAF-K8S-0901-003-AEAD-v1\n"
ARTIFACTS = ("checkpoint", "optimizer")
AAD_PREFIX = b"SAF-K8S-0901-003\x00PVC-AEAD-v1\x00"
SCRIPT = r'''import hashlib,json,os,secrets,sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MAGIC=b"SAF-K8S-0901-003-AEAD-v1\n"
AAD_PREFIX=b"SAF-K8S-0901-003\x00PVC-AEAD-v1\x00"
ARTIFACTS=("checkpoint","optimizer")
mode=sys.argv[1]
vault=Path("/vault")
key=None
if mode in ("write","restore","reject"):
    key=Path("/key/key").read_bytes()
    assert len(key)==32
def digest(value): return hashlib.sha256(value).hexdigest()
def aad(name): return AAD_PREFIX+name.encode("ascii")
def envelope(name,plaintext):
    nonce=secrets.token_bytes(12)
    return MAGIC+nonce+AESGCM(key).encrypt(nonce,plaintext,aad(name))
def split(raw):
    if not raw.startswith(MAGIC) or len(raw)<len(MAGIC)+12+16:
        raise ValueError("invalid envelope")
    return raw[len(MAGIC):len(MAGIC)+12],raw[len(MAGIC)+12:]
def restore(checkpoint_path):
    expected=json.loads(Path("/manifest/sha256").read_text())
    clear={}
    for name in ARTIFACTS:
        raw=Path(checkpoint_path if name=="checkpoint" else vault/(name+".aead")).read_bytes()
        nonce,cipher=split(raw)
        clear[name]=AESGCM(key).decrypt(nonce,cipher,aad(name))
        if digest(clear[name])!=expected[name]: raise ValueError("trusted digest mismatch")
    # No persistent destination is used. This location is a bounded memory-backed emptyDir.
    out=Path("/memory")
    out.mkdir(exist_ok=True)
    for name in ARTIFACTS: (out/(name+".restored")).write_bytes(clear[name])
    return {"both_auth_tags_valid":True,"trusted_digests_match":True,
            "checkpoint_sha256":digest(clear["checkpoint"]),
            "optimizer_sha256":digest(clear["optimizer"]),
            "restore_output_is_memory_backed":True}

result={"mode":mode}
if mode=="write":
    source=Path("/input")
    expected=json.loads(Path("/manifest/sha256").read_text())
    emitted={}
    for name in ARTIFACTS:
        plaintext=(source/name).read_bytes()
        if digest(plaintext)!=expected[name]: raise ValueError("source did not match trusted fixture digest")
        raw=envelope(name,plaintext)
        path=vault/(name+".aead")
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"wb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        emitted[name+"_envelope_sha256"]=digest(raw)
        emitted[name+"_envelope_size"]=len(raw)
    result.update(emitted=emitted,source_digests_match=True,result_ok=True)
elif mode=="observe":
    source=Path("/input")
    seen={}
    for name in ARTIFACTS:
        raw=(vault/(name+".aead")).read_bytes()
        seen[name+"_versioned_envelope"]=raw.startswith(MAGIC)
        seen[name+"_plaintext_absent"]=source.joinpath(name).read_bytes() not in raw
        seen[name+"_envelope_sha256"]=digest(raw)
        seen[name+"_envelope_size"]=len(raw)
    result.update(seen,all_ciphertexts_nonempty=all(seen[n+"_envelope_size"]>len(MAGIC)+28 for n in ARTIFACTS))
elif mode=="tamper":
    raw=(vault/"checkpoint.aead").read_bytes()
    nonce_start=len(MAGIC)
    flip_at=nonce_start+12+max(0,(len(raw)-nonce_start-12-16)//2)
    changed=bytearray(raw); changed[flip_at]^=1
    path=vault/"checkpoint.tampered.aead"
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as stream: stream.write(changed); stream.flush(); os.fsync(stream.fileno())
    result.update(original_envelope_sha256=digest(raw),tampered_envelope_sha256=digest(changed),
                  exact_copy_changed=(raw!=changed),source_envelope_unchanged=digest((vault/"checkpoint.aead").read_bytes())==digest(raw))
elif mode=="restore":
    result.update(restore(vault/"checkpoint.aead"))
elif mode=="reject":
    out=Path("/memory"); out.mkdir(exist_ok=True)
    expected=json.loads(Path("/manifest/sha256").read_text())
    checkpoint_ok=False; invalid_tag=False; outputs_absent=False
    try:
        # Authenticate and validate both artifacts before any restoration output is written.
        clear={}
        for name in ARTIFACTS:
            path=vault/("checkpoint.tampered.aead" if name=="checkpoint" else name+".aead")
            raw=path.read_bytes(); nonce,cipher=split(raw)
            clear[name]=AESGCM(key).decrypt(nonce,cipher,aad(name))
            if digest(clear[name])!=expected[name]: raise ValueError("trusted digest mismatch")
        checkpoint_ok=True
    except InvalidTag:
        invalid_tag=True
    outputs_absent=not any(out.iterdir())
    result.update(tampered_checkpoint_not_accepted=not checkpoint_ok,invalid_tag_observed=invalid_tag,
                  plaintext_outputs_absent=outputs_absent)
else: raise SystemExit(22)
print(json.dumps(result,sort_keys=True))
'''


def _labels():
    return {"saf-k8s.example/control": CONTROL_ID,
            "saf-k8s.example/fixture": "true"}


def _run(command, *, timeout=180, env=None):
    try:
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("bounded PVC AEAD helper command did not complete")
    if result.returncode:
        raise RuntimeError("bounded PVC AEAD helper command failed")
    return result.stdout


def _architecture():
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return "arm64", "aarch64", ("manylinux_2_28_aarch64", "manylinux2014_aarch64")
    if machine in ("x86_64", "amd64"):
        return "amd64", "x86_64", ("manylinux_2_28_x86_64", "manylinux2014_x86_64")
    raise RuntimeError("PVC AEAD image supports only Linux ARM64 or AMD64 hosts")


def _build_and_load_image(lab):
    arch, _, platforms = _architecture()
    image = IMAGE_PREFIX + arch
    case_dir = Path(__file__).resolve().parent
    expected_hashes = {
        "cryptography": {"arm64": "f9f6143a8c75945eb960d9eb98905a441394abfa24afaae239d514ffb2586480",
                         "amd64": "630ebfea3bf689d075f82316324ff7433dc447fe6bc1bfc76524b74b4a9567d2"},
        "cffi": {"arm64": "d48a880098c96020b02d5a1f7d9251308510ce8858940e6fa99ece33f610838b",
                 "amd64": "c8d3b5532fc71b7a77c09192b4a5a200ea992702734a2e9279a37f2478236f26"},
        "pycparser": {"arm64": "e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934",
                      "amd64": "e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934"},
    }
    with tempfile.TemporaryDirectory(prefix="saf-0901-003-pvc-aead-image-") as directory:
        context = Path(directory)
        wheelhouse = context / "wheelhouse"
        wheelhouse.mkdir()
        download = ["python3", "-m", "pip", "download", "--disable-pip-version-check",
                    "--isolated", "--index-url", "https://pypi.org/simple",
                    "--only-binary=:all:", "--require-hashes", "--no-deps",
                    "--dest", str(wheelhouse), "--python-version", "313",
                    "--implementation", "cp", "--abi", "cp313",
                    "-r", str(case_dir / "requirements-aead.txt")]
        for tag in platforms:
            download.extend(("--platform", tag))
        try:
            _run(download, timeout=120, env=lab.env)
        except RuntimeError:
            lab.block("Could not fetch the exact hash-pinned public ARM64/AMD64 AEAD wheels")
        wheel_hashes = {}
        for wheel in sorted(wheelhouse.glob("*.whl")):
            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            matched = next((name for name in expected_hashes
                            if wheel.name.lower().startswith(name + "-")), None)
            if matched is None or digest not in set(expected_hashes[matched].values()):
                lab.block("Offline AEAD wheel did not match an approved package hash")
            wheel_hashes[wheel.name] = digest
        if {name.split("-", 1)[0].lower() for name in wheel_hashes} != set(expected_hashes):
            lab.block("Offline AEAD build context is missing a required pinned wheel")
        for source, target in ((case_dir / "Dockerfile.aead", context / "Dockerfile"),
                               (case_dir / "requirements-aead.txt", context / "requirements-aead.txt")):
            target.write_bytes(source.read_bytes())
        try:
            build_output = _run(["docker", "build", "--network=none", "--platform", f"linux/{arch}",
                                 "-t", image, "-f", str(context / "Dockerfile"), str(context)],
                                timeout=300, env=lab.env)
            inspect = json.loads(_run(["docker", "image", "inspect", image], env=lab.env))[0]
            if inspect.get("Os") != "linux" or inspect.get("Architecture") != arch:
                lab.block("Derived AEAD image architecture differs from the host runtime")
            _run(["kind", "load", "docker-image", "--name", lab.cluster, image], timeout=180, env=lab.env)
        except (RuntimeError, json.JSONDecodeError, IndexError):
            lab.block("The offline AEAD runtime image could not be built and loaded into this case cluster")
        return {"image": image, "architecture": arch,
                "local_config_id": inspect.get("Id"),
                "repo_digests": inspect.get("RepoDigests", []),
                "wheel_sha256": wheel_hashes,
                "docker_build_completed": bool(build_output)}


def _quiet_kubectl(lab, *args, timeout=40, payload=None):
    try:
        result = subprocess.run(
            ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
             "--request-timeout=25s", *args], env=lab.env, input=payload,
            capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("The bounded PVC AEAD observation did not complete")
    if result.returncode:
        lab.block("A scoped PVC AEAD Kubernetes operation failed")
    return result.stdout


def _apply_secret(lab, key):
    obj = {"apiVersion": "v1", "kind": "Secret",
           "metadata": {"name": KEY_SECRET, "namespace": NAMESPACE, "labels": _labels()},
           "type": "Opaque", "data": {"key": base64.b64encode(key).decode("ascii")}}
    # Key bytes are supplied through a private temporary file, never command args or logs.
    with tempfile.TemporaryDirectory(prefix="saf-0901-003-aead-key-") as temp:
        path = Path(temp) / "key-secret.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(obj, separators=(",", ":")))
        _quiet_kubectl(lab, "-n", NAMESPACE, "apply", "-f", str(path), "-o", "name")


def _create(lab, obj):
    _quiet_kubectl(lab, "-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(obj))


def _job_object(mode):
    mounts = [
        {"name": "vault", "mountPath": "/vault", "readOnly": mode != "write" and mode != "tamper"},
        {"name": "code", "mountPath": "/code", "readOnly": True},
    ]
    volumes = [
        {"name": "vault", "persistentVolumeClaim": {"claimName": PVC}},
        {"name": "code", "configMap": {"name": CODE_CONFIG}},
    ]
    if mode in ("write", "observe"):
        mounts.append({"name": "input", "mountPath": "/input", "readOnly": True})
        volumes.append({"name": "input", "secret": {"secretName": CHECKPOINT_SECRET}})
    if mode in ("write", "restore", "reject"):
        mounts.append({"name": "key", "mountPath": "/key", "readOnly": True})
        volumes.append({"name": "key", "secret": {"secretName": KEY_SECRET}})
    if mode in ("write", "restore", "reject"):
        mounts.append({"name": "manifest", "mountPath": "/manifest", "readOnly": True})
        volumes.append({"name": "manifest", "configMap": {"name": MANIFEST_CONFIG}})
    if mode in ("restore", "reject"):
        mounts.append({"name": "memory", "mountPath": "/memory"})
        volumes.append({"name": "memory", "emptyDir": {"medium": "Memory", "sizeLimit": "8Mi"}})
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": JOB[mode], "namespace": NAMESPACE, "labels": _labels()},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
                 "template": {"metadata": {"labels": _labels()}, "spec": {
                     "restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "runAsGroup": 65534, "fsGroup": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "aead", "image": CURRENT_IMAGE,
                                     "imagePullPolicy": "Never",
                                     "command": ["python", "-B", "/code/pvc_aead.py", mode],
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}},
                                     "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                                   "limits": {"cpu": "200m", "memory": "128Mi"}},
                                     "volumeMounts": mounts}], "volumes": volumes}}}}


def _job_result(lab, mode):
    name = JOB[mode]
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        job = json.loads(_quiet_kubectl(lab, "-n", NAMESPACE, "get", f"job/{name}", "-o", "json"))
        conditions = {row.get("type") for row in job.get("status", {}).get("conditions", [])
                      if row.get("status") == "True"}
        if conditions & {"Complete", "Failed"}:
            pods = json.loads(_quiet_kubectl(
                lab, "-n", NAMESPACE, "get", "pods", "-l", f"batch.kubernetes.io/job-name={name}",
                "-o", "json")).get("items", [])
            if len(pods) != 1:
                lab.block("PVC AEAD Job did not own exactly one Pod")
            pod = pods[0]
            log = _quiet_kubectl(lab, "-n", NAMESPACE, "logs", f"pod/{pod['metadata']['name']}")
            try:
                result = json.loads(log.strip().splitlines()[-1])
            except (IndexError, json.JSONDecodeError):
                result = {}
            return job, pod, result, conditions
        time.sleep(1)
    lab.block(f"PVC AEAD Job {name} did not reach a bounded terminal condition")


def run(lab):
    image_provenance = _build_and_load_image(lab)
    key = secrets.token_bytes(32)
    script_config = {"apiVersion": "v1", "kind": "ConfigMap",
                     "metadata": {"name": CODE_CONFIG, "namespace": NAMESPACE, "labels": _labels()},
                     "immutable": True, "data": {"pvc_aead.py": SCRIPT}}
    _create(lab, script_config)
    _apply_secret(lab, key)
    _create(lab, {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                  "metadata": {"name": PVC, "namespace": NAMESPACE, "labels": _labels()},
                  "spec": {"accessModes": ["ReadWriteOnce"],
                           "resources": {"requests": {"storage": "64Mi"}}}})

    results = {}
    for mode in ("write", "observe", "tamper", "restore", "reject"):
        _create(lab, _job_object(mode))
        results[mode] = _job_result(lab, mode)

    pvc_obj = json.loads(_quiet_kubectl(lab, "-n", NAMESPACE, "get", f"pvc/{PVC}", "-o", "json"))
    pv_name = pvc_obj.get("spec", {}).get("volumeName")
    if not pv_name:
        lab.block("PVC AEAD claim did not bind to a persistent volume")
    pv_obj = json.loads(_quiet_kubectl(lab, "get", f"pv/{pv_name}", "-o", "json"))
    key_obj = json.loads(_quiet_kubectl(lab, "-n", NAMESPACE, "get", f"secret/{KEY_SECRET}", "-o", "json"))
    pvc_identity = {"name": pvc_obj.get("metadata", {}).get("name"),
                    "namespace": pvc_obj.get("metadata", {}).get("namespace"),
                    "uid": pvc_obj.get("metadata", {}).get("uid"),
                    "phase": pvc_obj.get("status", {}).get("phase"),
                    "pv_name": pv_name, "storage_class": pvc_obj.get("spec", {}).get("storageClassName"),
                    "pv_uid": pv_obj.get("metadata", {}).get("uid")}
    job_identity = {}
    for mode, (job, pod, result, conditions) in results.items():
        spec = job.get("spec", {}).get("template", {}).get("spec", {})
        container = spec.get("containers", [{}])[0]
        statuses = pod.get("status", {}).get("containerStatuses", [])
        status = statuses[0] if len(statuses) == 1 else {}
        owners = pod.get("metadata", {}).get("ownerReferences", [])
        controller_owner = next((owner for owner in owners
                                 if owner.get("controller") is True and owner.get("kind") == "Job"), {})
        mounts = {row.get("name"): {"path": row.get("mountPath"), "readOnly": row.get("readOnly", False)}
                  for row in container.get("volumeMounts", [])}
        claim_refs = {volume.get("name"): volume.get("persistentVolumeClaim", {}).get("claimName")
                      for volume in spec.get("volumes", []) if volume.get("persistentVolumeClaim")}
        job_identity[mode] = {"job_uid": job.get("metadata", {}).get("uid"),
                              "pod_uid": pod.get("metadata", {}).get("uid"),
                              "pod_controller_owner_job_uid": controller_owner.get("uid"),
                              "container_id": status.get("containerID"),
                              "runtime_image": status.get("image"),
                              "image_id": status.get("imageID"),
                              "node_name": pod.get("spec", {}).get("nodeName"),
                              "claim_refs": claim_refs, "mounts": mounts,
                              "secret_volumes": {volume.get("name"): volume.get("secret", {}).get("secretName")
                                                 for volume in spec.get("volumes", []) if volume.get("secret")},
                              "image": container.get("image"),
                              "image_pull_policy": container.get("imagePullPolicy"),
                              "condition_complete": "Complete" in conditions,
                              "result": result}

    cri_images = {}
    for node_name in sorted({row["node_name"] for row in job_identity.values() if row["node_name"]}):
        try:
            cri_images[node_name] = json.loads(_run(
                ["docker", "exec", node_name, "crictl", "inspecti", CURRENT_IMAGE],
                env=lab.env, timeout=45))
        except (RuntimeError, json.JSONDecodeError):
            lab.block("The exact node CRI image record could not be read")
    for mode, row in job_identity.items():
        status = cri_images.get(row["node_name"], {}).get("status", {})
        image_id = row.get("image_id") or ""
        image_digest = image_id.removeprefix("containerd://").rsplit("@", 1)[-1]
        repo_digests = status.get("repoDigests", [])
        config_id = status.get("id")
        matched_kind = ("config" if image_digest == config_id else
                        "manifest" if any(value.rsplit("@", 1)[-1] == image_digest for value in repo_digests)
                        else None)
        row["cri_image_match_kind"] = matched_kind
        row["cri_config_id"] = config_id
        row["cri_repo_digests"] = repo_digests
        row["cri_repo_tags"] = status.get("repoTags", [])
        row["cri_config_matches_local_docker_id"] = config_id == image_provenance.get("local_config_id")
        canonical_tag = "docker.io/library/" + CURRENT_IMAGE
        row["cri_image_binding_matches"] = bool(
            config_id and matched_kind
            and set(status.get("repoTags", [])) & {CURRENT_IMAGE, canonical_tag})

    writer_output = job_identity["write"]["result"].get("emitted", {})
    observer_result = job_identity["observe"]["result"]
    storage_pairs_match = all(
        writer_output.get(name + "_envelope_sha256") == observer_result.get(name + "_envelope_sha256")
        and writer_output.get(name + "_envelope_size") == observer_result.get(name + "_envelope_size")
        for name in ARTIFACTS)

    expected_input = {
        "checkpoint": hashlib.sha256(FIXTURE_BYTES["checkpoint"]).hexdigest(),
        "optimizer": hashlib.sha256(FIXTURE_BYTES["optimizer"]).hexdigest(),
    }
    write_ok = (job_identity["write"]["condition_complete"]
                and job_identity["write"]["result"].get("result_ok") is True
                and job_identity["write"]["result"].get("source_digests_match") is True
                and job_identity["write"]["claim_refs"] == {"vault": PVC})
    observe_result = observer_result
    observe_spec = job_identity["observe"]
    observe_keyless = KEY_SECRET not in set(observe_spec["secret_volumes"].values())
    observe_claim_readonly = observe_spec["mounts"].get("vault", {}).get("readOnly") is True
    observe_ok = (job_identity["observe"]["condition_complete"] and storage_pairs_match
                  and observe_keyless and observe_claim_readonly
                  and observe_result.get("all_ciphertexts_nonempty") is True
                  and all(observe_result.get(name+"_versioned_envelope") is True
                          and observe_result.get(name+"_plaintext_absent") is True
                          for name in ARTIFACTS))
    restore_result = job_identity["restore"]["result"]
    restore_ok = (job_identity["restore"]["condition_complete"]
                  and restore_result.get("both_auth_tags_valid") is True
                  and restore_result.get("trusted_digests_match") is True
                  and restore_result.get("restore_output_is_memory_backed") is True
                  and restore_result.get("checkpoint_sha256") == expected_input["checkpoint"]
                  and restore_result.get("optimizer_sha256") == expected_input["optimizer"])
    tamper_result = job_identity["tamper"]["result"]
    tamper_ok = (job_identity["tamper"]["condition_complete"]
                 and tamper_result.get("exact_copy_changed") is True
                 and tamper_result.get("source_envelope_unchanged") is True
                 and tamper_result.get("original_envelope_sha256")
                 == writer_output.get("checkpoint_envelope_sha256")
                 and tamper_result.get("original_envelope_sha256") != tamper_result.get("tampered_envelope_sha256"))
    reject_result = job_identity["reject"]["result"]
    reject_ok = (job_identity["reject"]["condition_complete"]
                 and reject_result.get("invalid_tag_observed") is True
                 and reject_result.get("tampered_checkpoint_not_accepted") is True
                 and reject_result.get("plaintext_outputs_absent") is True)
    exact_job_scope = all(
        row["image"] == CURRENT_IMAGE and row["claim_refs"] == {"vault": PVC}
        and row["image_pull_policy"] == "Never" and bool(row["container_id"])
        and bool(row["pod_uid"]) and row["pod_controller_owner_job_uid"] == row["job_uid"]
        and row["cri_image_binding_matches"]
        for row in job_identity.values())
    expected_secret_volumes = {
        "write": {"input": CHECKPOINT_SECRET, "key": KEY_SECRET},
        "observe": {"input": CHECKPOINT_SECRET},
        "tamper": {},
        "restore": {"key": KEY_SECRET},
        "reject": {"key": KEY_SECRET},
    }
    key_scope_exact = all(row["secret_volumes"] == expected_secret_volumes[mode]
                          for mode, row in job_identity.items())
    volume_mount_scope_exact = (
        job_identity["observe"]["mounts"].get("vault", {}).get("readOnly") is True
        and job_identity["restore"]["mounts"].get("vault", {}).get("readOnly") is True
        and job_identity["reject"]["mounts"].get("vault", {}).get("readOnly") is True
        and job_identity["write"]["mounts"].get("vault", {}).get("readOnly") is False
        and job_identity["tamper"]["mounts"].get("vault", {}).get("readOnly") is False)
    identity_ok = (pvc_identity["phase"] == "Bound" and bool(pvc_identity["uid"])
                   and bool(pvc_identity["pv_uid"]) and key_obj.get("metadata", {}).get("uid")
                   and all(row["condition_complete"] for row in job_identity.values())
                   and exact_job_scope and key_scope_exact and volume_mount_scope_exact
                   and pv_obj.get("spec", {}).get("claimRef", {}).get("uid") == pvc_identity["uid"]
                   and pv_obj.get("spec", {}).get("claimRef", {}).get("name") == PVC
                   and pv_obj.get("spec", {}).get("claimRef", {}).get("namespace") == NAMESPACE)

    raw = {"scope": "synthetic checkpoint and optimizer protected with application-layer AES-GCM before write to one case-owned PVC; no backend/media encryption claim",
           "pvc_identity": pvc_identity,
           "image_provenance": image_provenance,
           "cri_images": cri_images,
           "ephemeral_key_secret_identity": {"name": KEY_SECRET,
                                              "uid": key_obj.get("metadata", {}).get("uid"),
                                              "resource_version": key_obj.get("metadata", {}).get("resourceVersion"),
                                              "key_bytes_retained": False},
           "jobs": job_identity,
           "writer_observer_storage_pairs_match": storage_pairs_match,
           "expected_plaintext_sha256": expected_input,
           "cryptography_version": "50.0.2",
           "algorithm": "AES-256-GCM", "nonce_length_bytes": 12,
           "associated_data_bound_to": [CONTROL_ID, "PVC-AEAD-v1", "artifact-name"],
           "production_key_or_checkpoint": False, "underlying_storage_encryption_assessed": False}
    (lab.evidence / "checkpoint-pvc-aead.raw.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")

    lab.check("pvc-aead-write", "Checkpoint and optimizer match trusted input digests and are AEAD-encrypted before their PVC write",
              write_ok and identity_ok,
              {"job_complete": write_ok, "pvc_bound": identity_ok})
    lab.check("pvc-aead-observer", "A separate keyless read-only Pod observes nonempty envelopes without fixture plaintext",
              observe_ok, {"read_only": observe_claim_readonly,
                           "keyless": observe_keyless,
                           "envelopes_present": observe_result.get("all_ciphertexts_nonempty") is True,
                           "fixture_plaintext_absent": all(observe_result.get(n+"_plaintext_absent") is True for n in ARTIFACTS)})
    lab.check("pvc-aead-restore", "Authorized restore authenticates both artifacts and checks trusted digests before memory-only output",
              restore_ok, {"both_auth_tags_valid": restore_result.get("both_auth_tags_valid") is True,
                           "trusted_digests_match": restore_result.get("trusted_digests_match") is True,
                           "exact_fixture_digests": restore_ok,
                           "memory_only_output": restore_result.get("restore_output_is_memory_backed") is True})
    lab.check("pvc-aead-tamper", "A controlled changed copy is distinct while the valid PVC envelope remains unchanged",
              tamper_ok, {"changed_copy_created": tamper_result.get("exact_copy_changed") is True,
                          "valid_envelope_preserved": tamper_result.get("source_envelope_unchanged") is True})
    lab.check("pvc-aead-reject", "Altered ciphertext fails AEAD before any plaintext restore output is created",
              reject_ok, {"authentication_rejected": reject_result.get("invalid_tag_observed") is True,
                          "tampered_checkpoint_not_accepted": reject_result.get("tampered_checkpoint_not_accepted") is True,
                          "plaintext_output_absent": reject_result.get("plaintext_outputs_absent") is True})


def _load_fixture():
    path = Path(__file__).resolve().parent / "fixture.json"
    return json.loads(path.read_text(encoding="utf-8"))


_fixture = _load_fixture()
CHECKPOINT_SECRET = _fixture["checkpoint_name"]
MANIFEST_CONFIG = _fixture["manifest_name"]
_arch_name, _, _ = _architecture()
CURRENT_IMAGE = IMAGE_PREFIX + _arch_name
FIXTURE_BYTES = {
    "checkpoint": _fixture["checkpoint_bytes"].encode("ascii"),
    "optimizer": json.dumps(_fixture["optimizer"], sort_keys=True, separators=(",", ":")).encode(),
}
