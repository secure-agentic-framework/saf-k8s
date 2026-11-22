"""Verify native re-encryption of two synthetic core Secrets on disposable kind."""
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import time


NODE_IMAGE = (
    "kindest/node:v1.37.0@sha256:"
    "a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
)
SCOPE = (
    "Kubernetes v1.37.0 kind; two named inert synthetic core Secrets in the "
    "case-owned namespace plus one synthetic write sentinel. A resource-scoped secrets StorageVersionMigration "
    "runs only on the disposable case cluster. The test does not establish "
    "production KMS scheduling, audit, inventory, or retirement."
)

NAMESPACE = "saf-0403-011-fixtures"
FIXTURES = {
    "saf-k8s-0403-011-old-a": "saf-k8s-0403-011-inert-marker-a",
    "saf-k8s-0403-011-old-b": "saf-k8s-0403-011-inert-marker-b",
}
SENTINEL = "saf-k8s-0403-011-reload"
SENTINEL_MARKER = "saf-k8s-0403-011-inert-reload-marker"
CONFIG_DIR = "/etc/kubernetes/saf-0403-011-encryption"
OLD_LABEL = "saf-old"
NEW_LABEL = "saf-new"
MIGRATION_NAME = "saf-0403-011-secret-rewrite"


def _write_config(path: Path, keys: list[dict]) -> None:
    """Write Secretbox config atomically with restrictive local permissions."""
    payload = json.dumps({
        "apiVersion": "apiserver.config.k8s.io/v1",
        "kind": "EncryptionConfiguration",
        "resources": [{
            "resources": ["secrets"],
            "providers": [{"secretbox": {"keys": keys}}],
        }],
    })
    replacement = path.with_name(path.name + ".next")
    fd = os.open(replacement, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    replacement.replace(path)
    path.chmod(0o600)


def prepare_kind(lab, temporary: Path) -> Path:
    """Prepare pinned-kind config and keep ephemeral config state for run()."""
    root = temporary.resolve()
    mounted = root / "encryption"
    mounted.mkdir(mode=0o700, parents=True, exist_ok=True)
    config = mounted / "provider.json"
    old_key = {
        "name": OLD_LABEL,
        "secret": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
    }
    _write_config(config, [old_key])
    # Do not retain key bytes in module state or emit them to the runner/evidence.
    del old_key

    kind_config = root / "kind.yaml"
    kind_config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(mounted))}
    containerPath: {CONFIG_DIR}
    readOnly: true
kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta4
  kind: ClusterConfiguration
  apiServer:
    extraArgs:
    - name: encryption-provider-config
      value: {CONFIG_DIR}/provider.json
    - name: encryption-provider-config-automatic-reload
      value: "true"
    extraVolumes:
    - name: saf-0403-011-encryption
      hostPath: {CONFIG_DIR}
      mountPath: {CONFIG_DIR}
      readOnly: true
      pathType: Directory
""", encoding="utf-8")
    kind_config.chmod(0o600)
    return kind_config


def _kubectl(lab, *args, payload=None, timeout=45):
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
               f"kind-{lab.cluster}", f"--request-timeout={timeout - 5}s", *args]
    try:
        result = subprocess.run(command, input=payload, text=True, capture_output=True,
                                env=lab.env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("The isolated Secret rewrite probe could not complete")
    if result.returncode:
        # Never retain output: even an unexpected API response can contain data.
        lab.block("An isolated Kubernetes API request failed without retaining its output")
    return result.stdout


def _create_fixture(lab, name, marker):
    body = {
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "type": "Opaque",
        "data": {"marker": base64.b64encode(marker.encode()).decode("ascii")},
    }
    _kubectl(lab, "create", "-f", "-", "-o", "name", payload=json.dumps(body))


def _exact_envelope(lab, name):
    """Read one exact etcd key and return label/visibility booleans only."""
    marker = SENTINEL_MARKER if name == SENTINEL else FIXTURES[name]
    exact_key = f"/registry/secrets/{NAMESPACE}/{name}"
    output = _kubectl(
        lab, "-n", "kube-system", "exec", f"etcd-{lab.cluster}-control-plane",
        "-c", "etcd", "--", "etcdctl", "--endpoints=https://127.0.0.1:2379",
        "--cacert=/etc/kubernetes/pki/etcd/ca.crt",
        "--cert=/etc/kubernetes/pki/etcd/server.crt",
        "--key=/etc/kubernetes/pki/etcd/server.key",
        "get", exact_key, "--write-out=json", timeout=30,
    )
    try:
        rows = json.loads(output).get("kvs", [])
        if len(rows) != 1 or base64.b64decode(rows[0]["key"], validate=True).decode() != exact_key:
            lab.block("etcd did not return exactly the requested synthetic Secret record")
        value = base64.b64decode(rows[0]["value"], validate=True)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        lab.block("The exact synthetic Secret record could not be safely classified")
    # Discard the raw bytes immediately; only sanitized classifications escape.
    label = next((candidate for candidate in (OLD_LABEL, NEW_LABEL)
                  if value.startswith(f"k8s:enc:secretbox:v1:{candidate}:".encode())), None)
    marker_visible = marker.encode() in value
    del value, output
    return {"key_label": label, "marker_visible": marker_visible}


def _api_marker_matches(lab, name):
    """Read one named Secret in memory; return only whether its marker matches."""
    output = _kubectl(lab, "-n", NAMESPACE, "get", "secret", name, "-o", "json")
    try:
        actual = json.loads(output).get("data", {}).get("marker", "")
        decoded = base64.b64decode(actual, validate=True).decode("utf-8")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        decoded = ""
    matches = decoded == FIXTURES[name]
    del output, decoded
    return matches


def _set_write_key(config):
    """Install a new primary write key while retaining the old read key."""
    # The local key material is generated afresh and never logged or retained.
    new_key = {
        "name": NEW_LABEL,
        "secret": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
    }
    # Re-use the old key material already present in the private config, without
    # printing it. The JSON exists only in the disposable temporary directory.
    existing = json.loads(config.read_text(encoding="utf-8"))
    old_key = existing["resources"][0]["providers"][0]["secretbox"]["keys"][0]
    _write_config(config, [new_key, old_key])
    del new_key, old_key, existing


def _rewrite(lab):
    version = json.loads(_kubectl(lab, "version", "-o", "json"))["serverVersion"]["gitVersion"]
    discovery = json.loads(_kubectl(lab, "get", "--raw=/apis/storagemigration.k8s.io/v1"))
    has_svm = any(row.get("name") == "storageversionmigrations"
                  for row in discovery.get("resources", []))
    lab.check("positive", "Pinned Kubernetes v1.37.0 serves StorageVersionMigration v1",
              version == "v1.37.0" and has_svm,
              {"kubernetes_v1_37": version == "v1.37.0", "svm_v1_discovered": has_svm})

    _kubectl(lab, "create", "namespace", NAMESPACE)
    for name, marker in FIXTURES.items():
        _create_fixture(lab, name, marker)
    old = {"key_label": OLD_LABEL, "marker_visible": False}
    initial = [_exact_envelope(lab, name) for name in FIXTURES]
    lab.check("red", "Both named fixture Secrets initially use the old encrypted envelope",
              initial == [old, old], initial)
    initial_markers = [_api_marker_matches(lab, name) for name in FIXTURES]
    lab.check("positive", "Both named fixture reads match their original inert markers",
              initial_markers == [True, True], {"both_markers_match": all(initial_markers)})

    config = lab.kubeconfig.parent / "encryption" / "provider.json"
    _set_write_key(config)
    _create_fixture(lab, SENTINEL, SENTINEL_MARKER)
    new = {"key_label": NEW_LABEL, "marker_visible": False}
    deadline = time.monotonic() + 130
    observed = None
    while time.monotonic() < deadline:
        # Only the sentinel is changed while waiting for the new write key.
        _kubectl(lab, "-n", NAMESPACE, "annotate", f"secret/{SENTINEL}",
                 f"saf-k8s.example/reload-probe={time.monotonic_ns()}", "--overwrite")
        observed = _exact_envelope(lab, SENTINEL)
        if observed == new:
            break
        time.sleep(5)
    lab.check("positive", "A fresh Secret write uses the new key after config reload",
              observed == new, observed)
    before_migration = [_exact_envelope(lab, name) for name in FIXTURES]
    lab.check("red", "Both previously existing records retain the old envelope after reload",
              before_migration == [old, old], before_migration)

    migration = {
        "apiVersion": "storagemigration.k8s.io/v1", "kind": "StorageVersionMigration",
        "metadata": {"name": MIGRATION_NAME},
        "spec": {"resource": {"group": "", "resource": "secrets"}},
    }
    _kubectl(lab, "create", "-f", "-", "-o", "name", payload=json.dumps(migration))
    deadline = time.monotonic() + 180
    conditions = {}
    reason = None
    while time.monotonic() < deadline:
        status = json.loads(_kubectl(
            lab, "get", f"storageversionmigration/{MIGRATION_NAME}", "-o", "json"))
        condition_rows = status.get("status", {}).get("conditions", [])
        conditions = {row.get("type"): row.get("status") for row in condition_rows}
        reason = next((row.get("reason") for row in condition_rows
                       if row.get("type") == "Succeeded"), None)
        if conditions.get("Succeeded") == "True" or conditions.get("Failed") == "True":
            break
        time.sleep(2)
    succeeded = (conditions.get("Succeeded") == "True"
                 and conditions.get("Failed") != "True"
                 and reason == "StorageVersionMigrationSucceeded")
    lab.check("green", "Native core Secret StorageVersionMigration reports success",
              succeeded,
              {"succeeded": succeeded, "failed": conditions.get("Failed") == "True",
               "expected_reason": reason == "StorageVersionMigrationSucceeded"})

    final_envelopes = [_exact_envelope(lab, name) for name in FIXTURES]
    lab.check("green", "Both named fixture records now use the new encrypted envelope",
              final_envelopes == [new, new],
              final_envelopes)
    final_markers = [_api_marker_matches(lab, name) for name in FIXTURES]
    lab.check("positive", "Both fixture reads preserve their original inert markers",
              final_markers == [True, True], {"both_original_markers_match": all(final_markers)})


def run(lab):
    """Run on the regular runner's fresh cluster; this hook never creates a cluster."""
    _rewrite(lab)
