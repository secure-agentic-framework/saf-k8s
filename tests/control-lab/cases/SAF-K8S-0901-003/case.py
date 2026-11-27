"""Exercise encrypted API storage, scoped workload access, and exact restore."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

from lab import NAMESPACE, NODE_IMAGE


HERE = Path(__file__).resolve().parent
CONTROL_ID = "SAF-K8S-0901-003"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
ENCRYPTION_DESTINATION = "/etc/kubernetes/saf-checkpoint-encryption.yaml"
FIXTURE = json.loads((HERE / "fixture.json").read_text(encoding="utf-8"))
MARKER = b"SYNTHETIC CHECKPOINT FIXTURE 0901-003"
CHECKPOINT = FIXTURE["checkpoint_bytes"].encode("ascii")
OPTIMIZER = json.dumps(FIXTURE["optimizer"], sort_keys=True, separators=(",", ":")).encode()
NAMES = {
    "checkpoint": FIXTURE["checkpoint_name"],
    "tampered": FIXTURE["tampered_name"],
    "restore": FIXTURE["restore_name"],
    "manifest": FIXTURE["manifest_name"],
    "configmap": "saf-0901-003-plaintext-control",
    "workload_config": "saf-0901-003-mock-workload",
}
SCOPE = (
    "One disposable Kind Kubernetes v1.36.1 cluster with an ephemeral Secretbox "
    "EncryptionConfiguration for core Secret API objects, one small synthetic checkpoint, "
    "synthetic optimizer metadata, and one unencrypted ConfigMap comparator. Exact etcd "
    "records are checked inside the case cluster. Namespaced Roles grant named GET/UPDATE "
    "only for the mock trainer's restore Secret, and named GET for checkpoint inputs and "
    "the digest manifest; a separate observer can GET only the restore Secret. An ordinary "
    "mock Pod demonstrates denied Secret GET/PATCH. A second untrusted request attempts a "
    "metadata-only patch to the exact checkpoint input Secret; an independent API readback "
    "checks its UID, resourceVersion, and data hashes remain unchanged. This does not test filesystem/PV or cloud "
    "object-store encryption, KMS/key custody or rotation, production identities, human "
    "authorization, distributed storage, or actual ML training."
)


def prepare_kind(lab, temporary):
    """Create the ephemeral key/config before the runner starts the cluster."""
    config = temporary / "0901-003-encryption.yaml"
    key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    template = (HERE / "encryption-config.yaml").read_text(encoding="utf-8")
    descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(template.replace("__EPHEMERAL_BASE64_KEY__", key))
    kind_config = temporary / "0901-003-kind.yaml"
    kind_config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(config))}
    containerPath: {ENCRYPTION_DESTINATION}
    readOnly: true
kubeadmConfigPatches:
- |
  kind: ClusterConfiguration
  apiVersion: kubeadm.k8s.io/v1beta4
  apiServer:
    extraArgs:
    - name: encryption-provider-config
      value: {ENCRYPTION_DESTINATION}
    extraVolumes:
    - name: saf-checkpoint-encryption
      hostPath: {ENCRYPTION_DESTINATION}
      mountPath: {ENCRYPTION_DESTINATION}
      readOnly: true
      pathType: File
""", encoding="utf-8")
    return kind_config


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def secret(name, checkpoint, optimizer):
    return {
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": {
            "saf-k8s.example/control": CONTROL_ID,
            "saf-k8s.example/synthetic": "true",
        }},
        "type": "Opaque",
        "data": {"checkpoint": b64(checkpoint), "optimizer": b64(optimizer)},
    }


def named_role(name, rules):
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": name, "namespace": NAMESPACE}, "rules": rules}


def named_binding(name, account, role):
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "subjects": [{"kind": "ServiceAccount", "name": account, "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role},
    }


def resource_fixtures():
    checkpoint_hash = hashlib.sha256(CHECKPOINT).hexdigest()
    optimizer_hash = hashlib.sha256(OPTIMIZER).hexdigest()
    expected = {
        "checkpoint_name": NAMES["checkpoint"], "tampered_name": NAMES["tampered"],
        "restore_name": NAMES["restore"], "manifest_name": NAMES["manifest"],
        "checkpoint_bytes": CHECKPOINT.decode("ascii"),
        "optimizer": json.loads(OPTIMIZER),
    }
    data = [
        secret(NAMES["checkpoint"], CHECKPOINT, OPTIMIZER),
        # Different benign bytes retain the trusted manifest hashes.
        secret(NAMES["tampered"], CHECKPOINT.replace(b"step=7", b"step=8"), OPTIMIZER),
        secret(NAMES["restore"], b"", b"{}"),
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": NAMES["manifest"], "namespace": NAMESPACE},
         "data": {"sha256": json.dumps({"checkpoint": checkpoint_hash,
                                          "optimizer": optimizer_hash}, sort_keys=True)}},
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": NAMES["configmap"], "namespace": NAMESPACE},
         "data": {"fixture": CHECKPOINT.decode("ascii")}},
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": NAMES["workload_config"], "namespace": NAMESPACE},
         "data": {"fixture.json": json.dumps(expected, sort_keys=True),
                  "mock_workload.py": (HERE / "mock_workload.py").read_text(encoding="utf-8")}},
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {
            "name": "saf-0901-003-trainer", "namespace": NAMESPACE}},
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {
            "name": "saf-0901-003-observer", "namespace": NAMESPACE}},
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {
            "name": "saf-0901-003-untrusted", "namespace": NAMESPACE}},
        named_role("saf-0901-003-trainer", [
            {"apiGroups": [""], "resources": ["secrets"], "resourceNames": [
                NAMES["checkpoint"], NAMES["tampered"]], "verbs": ["get"]},
            {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [
                NAMES["manifest"]], "verbs": ["get"]},
            {"apiGroups": [""], "resources": ["secrets"], "resourceNames": [
                NAMES["restore"]], "verbs": ["get", "update"]},
        ]),
        named_role("saf-0901-003-observer", [
            {"apiGroups": [""], "resources": ["secrets"], "resourceNames": [
                NAMES["restore"]], "verbs": ["get"]},
        ]),
        named_binding("saf-0901-003-trainer", "saf-0901-003-trainer", "saf-0901-003-trainer"),
        named_binding("saf-0901-003-observer", "saf-0901-003-observer", "saf-0901-003-observer"),
    ]
    return data


def apply_fixtures(lab):
    # Secret bytes never enter the runner's command log: kubectl reads a private,
    # mode-0600 temporary manifest by path, and emits only resource names.
    with tempfile.TemporaryDirectory(prefix="saf-0901-003-fixtures-") as temp:
        manifest = Path(temp) / "owned-fixtures.json"
        descriptor = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps({"apiVersion": "v1", "kind": "List",
                                     "items": resource_fixtures()}))
        result = subprocess.run(
            ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
             "--namespace", NAMESPACE, "--request-timeout=25s", "apply", "-f", str(manifest),
             "-o", "name"], env=lab.env, capture_output=True, text=True, timeout=40)
        if result.returncode:
            lab.block("Could not create case-owned synthetic checkpoint fixtures")


def quiet_kubectl(lab, *args, timeout=35):
    try:
        result = subprocess.run(
            ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
             "--request-timeout=25s", *args], env=lab.env, capture_output=True,
            text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("A scoped case-owned Kubernetes observation did not complete")
    if result.returncode:
        lab.block("A scoped case-owned Kubernetes observation failed; raw response was discarded")
    return result.stdout


def backend_record(lab, resource, name):
    key = f"/registry/{resource}/{NAMESPACE}/{name}"
    etcd_pod = f"etcd-{lab.cluster}-control-plane"
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
               "-n", "kube-system", "exec", etcd_pod, "-c", "etcd", "--", "etcdctl",
               "--endpoints=https://127.0.0.1:2379",
               "--cacert=/etc/kubernetes/pki/etcd/ca.crt",
               "--cert=/etc/kubernetes/pki/etcd/server.crt",
               "--key=/etc/kubernetes/pki/etcd/server.key", "get", key, "--write-out=json"]
    try:
        result = subprocess.run(command, env=lab.env, capture_output=True, text=True, timeout=40)
        records = json.loads(result.stdout).get("kvs", []) if result.returncode == 0 else []
        if len(records) != 1 or base64.b64decode(records[0]["key"], validate=True).decode() != key:
            lab.block("etcd did not return exactly the owned fixture record")
        raw = base64.b64decode(records[0]["value"], validate=True)
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, json.JSONDecodeError):
        lab.block("The exact case-owned backend record could not be inspected safely")
    return {"secretbox_prefix": raw.startswith(b"k8s:enc:secretbox:v1:"),
            "checkpoint_marker_present": MARKER in raw}


def checkpoint_source_state(lab):
    raw = quiet_kubectl(lab, "-n", NAMESPACE, "get", f"secret/{NAMES['checkpoint']}", "-o", "json")
    secret_object = json.loads(raw)
    try:
        data = secret_object["data"]
        checkpoint = base64.b64decode(data["checkpoint"], validate=True)
        optimizer = base64.b64decode(data["optimizer"], validate=True)
    except (KeyError, ValueError, TypeError):
        lab.block("The protected checkpoint source Secret could not be read safely")
    metadata = secret_object.get("metadata", {})
    annotations = metadata.get("annotations", {}) or {}
    return {
        "uid": metadata.get("uid"),
        "resource_version": metadata.get("resourceVersion"),
        "checkpoint_sha256": hashlib.sha256(checkpoint).hexdigest(),
        "optimizer_sha256": hashlib.sha256(optimizer).hexdigest(),
        "untrusted_source_write_annotation_present": (
            "saf-k8s.example/untrusted-source-write" in annotations),
    }


def pod_manifest(name, account, mode):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/control": CONTROL_ID}},
        "spec": {
            "restartPolicy": "Never", "serviceAccountName": account,
            "automountServiceAccountToken": True,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "mock-checkpoint-client", "image": PYTHON_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "/fixture/mock_workload.py", mode],
                "env": [{"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}}],
                "securityContext": {"readOnlyRootFilesystem": True,
                                    "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]}},
                "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                              "limits": {"cpu": "100m", "memory": "96Mi"}},
                "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
            }],
            "volumes": [{"name": "fixture", "configMap": {"name": NAMES["workload_config"],
                                                           "defaultMode": 0o444}}],
        },
    }


def run_pod(lab, name, account, mode):
    pod = pod_manifest(name, account, mode)
    # Pod manifests contain no checkpoint or credential bytes; the bounded
    # mock result is safe to retain as raw evidence.
    lab.kubectl("create", "-f", "-", "-o", "name", payload=json.dumps(pod))
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        status = json.loads(quiet_kubectl(lab, "-n", NAMESPACE, "get", f"pod/{name}", "-o", "json"))
        phase = status.get("status", {}).get("phase")
        if phase in {"Succeeded", "Failed"}:
            break
        time.sleep(1)
    else:
        lab.block(f"Mock workload {name} did not reach a terminal state")
    terminated = status.get("status", {}).get("containerStatuses", [{}])[0].get("state", {}).get("terminated", {})
    if phase != "Succeeded" or terminated.get("exitCode") != 0:
        lab.block(f"Mock workload {name} failed; raw container diagnostics were excluded")
    try:
        line = quiet_kubectl(lab, "-n", NAMESPACE, "logs", f"pod/{name}").strip().splitlines()[-1]
        return json.loads(line)
    except (ValueError, IndexError, json.JSONDecodeError):
        lab.block(f"Mock workload {name} did not emit its bounded result record")


def run(lab):
    apply_fixtures(lab)
    plain = backend_record(lab, "configmaps", NAMES["configmap"])
    lab.check("red", "The synthetic ConfigMap comparator is stored in cleartext",
              plain == {"secretbox_prefix": False, "checkpoint_marker_present": True}, plain)

    encrypted = backend_record(lab, "secrets", NAMES["checkpoint"])
    encrypted_ok = encrypted == {"secretbox_prefix": True, "checkpoint_marker_present": False}
    lab.check("green", "The checkpoint Secret is ciphertext in etcd and hides its fixture bytes",
              encrypted_ok, encrypted)

    trainer = run_pod(lab, "saf-0901-003-trainer-run", "saf-0901-003-trainer", "trainer")
    lab.check("red", "A changed checkpoint fails its detached digest check before restore",
              trainer.get("tampered_checkpoint_rejected") is True
              and trainer.get("restore_attempted_for_tampered_source") is False
              and trainer.get("tampered_get_status") == 200 and trainer.get("tampered_manifest_status") == 200,
              {"rejected": trainer.get("tampered_checkpoint_rejected"),
               "restore_attempted": trainer.get("restore_attempted_for_tampered_source")})

    denied = run_pod(lab, "saf-0901-003-untrusted-run", "saf-0901-003-untrusted", "unauthorized")
    lab.check("green", "An unbound workload identity is denied checkpoint read and restore write",
              denied == {"checkpoint_get_status": 403, "restore_patch_status": 403}, denied)

    source_before_untrusted_patch = checkpoint_source_state(lab)
    source_write = run_pod(lab, "saf-0901-003-untrusted-source-write-run",
                           "saf-0901-003-untrusted", "unauthorized_checkpoint_write")
    source_after_untrusted_patch = checkpoint_source_state(lab)
    expected_checkpoint = hashlib.sha256(CHECKPOINT).hexdigest()
    expected_optimizer = hashlib.sha256(OPTIMIZER).hexdigest()
    source_uid_unchanged = (source_before_untrusted_patch["uid"] is not None
                            and source_before_untrusted_patch["uid"] == source_after_untrusted_patch["uid"])
    source_revision_unchanged = (source_before_untrusted_patch["resource_version"] is not None
                                 and source_before_untrusted_patch["resource_version"]
                                 == source_after_untrusted_patch["resource_version"])
    checkpoint_hash_unchanged = (
        source_before_untrusted_patch["checkpoint_sha256"] == expected_checkpoint
        and source_after_untrusted_patch["checkpoint_sha256"] == expected_checkpoint)
    optimizer_hash_unchanged = (
        source_before_untrusted_patch["optimizer_sha256"] == expected_optimizer
        and source_after_untrusted_patch["optimizer_sha256"] == expected_optimizer)
    marker_absent = (not source_before_untrusted_patch["untrusted_source_write_annotation_present"]
                     and not source_after_untrusted_patch["untrusted_source_write_annotation_present"])
    source_write_denied = source_write.get("checkpoint_source_patch_status") == 403
    lab.check("source-write-denied",
              "An unbound workload cannot patch the named checkpoint input Secret and its identity and contents remain unchanged",
              source_write_denied and source_uid_unchanged and source_revision_unchanged
              and checkpoint_hash_unchanged and optimizer_hash_unchanged and marker_absent,
              {"checkpoint_source_patch_status": source_write.get("checkpoint_source_patch_status"),
               "source_uid_unchanged": source_uid_unchanged,
               "source_resource_version_unchanged": source_revision_unchanged,
               "checkpoint_sha256_unchanged": checkpoint_hash_unchanged,
               "optimizer_sha256_unchanged": optimizer_hash_unchanged,
               "untrusted_annotation_absent": marker_absent})

    observer = run_pod(lab, "saf-0901-003-observer-run", "saf-0901-003-observer", "observer")
    exact = (observer.get("get_status") == 200 and observer.get("exact_restore") is True
             and observer.get("checkpoint_sha256") == expected_checkpoint
             and observer.get("optimizer_sha256") == expected_optimizer
             and trainer.get("valid_checkpoint") is True
             and trainer.get("restore_update_status") == 200)
    lab.check("positive", "The authorized mock trainer restores validated bytes for an independent exact-content read",
              exact, {"trainer_validation": trainer.get("valid_checkpoint"),
                      "restore_update_status": trainer.get("restore_update_status"),
                      "observer_get_status": observer.get("get_status"),
                      "observer_exact_restore": observer.get("exact_restore"),
                      "checkpoint_sha256_matches": observer.get("checkpoint_sha256") == expected_checkpoint,
                      "optimizer_sha256_matches": observer.get("optimizer_sha256") == expected_optimizer})

    role = json.loads(quiet_kubectl(lab, "-n", NAMESPACE, "get", "role",
                                    "saf-0901-003-trainer", "-o", "json"))
    expected_rules = next(item["rules"] for item in resource_fixtures()
                          if item["kind"] == "Role" and item["metadata"]["name"] == "saf-0901-003-trainer")
    role_exact = role.get("rules") == expected_rules
    binding = json.loads(quiet_kubectl(lab, "-n", NAMESPACE, "get", "rolebinding",
                                       "saf-0901-003-trainer", "-o", "json"))
    expected_binding = named_binding("saf-0901-003-trainer", "saf-0901-003-trainer",
                                     "saf-0901-003-trainer")
    binding_exact = (binding["roleRef"] == expected_binding["roleRef"]
                     and binding["subjects"] == expected_binding["subjects"])
    lab.check("positive", "Trainer RBAC grants only named API operations in the owned namespace",
              role_exact and binding_exact,
              {"trainer_role_matches_expected_rules": role_exact,
               "trainer_rolebinding_matches_expected_subject": binding_exact})
    (lab.evidence / "checkpoint-observations.raw.json").write_text(json.dumps({
        "plaintext_backend_comparator": plain,
        "encrypted_backend_record": encrypted,
        "trainer": trainer, "unbound_workload": denied, "independent_observer": observer,
        "unbound_source_write": source_write,
        "checkpoint_source_before_untrusted_patch": source_before_untrusted_patch,
        "checkpoint_source_after_untrusted_patch": source_after_untrusted_patch,
        "role_rules": role.get("rules"), "binding_subjects": binding["subjects"],
        "kept_key_and_backend_payload_private": True,
    }, indent=2, sort_keys=True) + "\n")

    # Additive case-owned PVC data-plane proof. It is deliberately isolated in a
    # helper so the seven published assertions above retain their exact source.
    spec = importlib.util.spec_from_file_location("saf_0901_003_pvc_aead", HERE / "pvc_aead.py")
    if spec is None or spec.loader is None:
        lab.block("PVC AEAD supplement module could not be loaded")
    pvc_aead = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pvc_aead)
    pvc_aead.run(lab)
