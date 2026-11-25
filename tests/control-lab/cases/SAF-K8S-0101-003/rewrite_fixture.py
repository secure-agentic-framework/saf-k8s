"""Verify one synthetic Secret is actually rewritten after a native encryption reload."""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

from lab import NAMESPACE, NODE_IMAGE


SCOPE = (
    "One exact synthetic Secret on a disposable Kubernetes v1.36.1 kind API. "
    "Create under identity, switch the case-owned API server configuration to "
    "local Secretbox, verify the old exact record remains plaintext until an "
    "API update rewrites that same object, then verify ciphertext and API read."
)
NAME = "saf-rewrite-encryption-probe"
MARKER = "saf-k8s-public-synthetic-rewrite-0101-003"
ANNOTATION = "saf-k8s.example/rewrite-marker"
PREFIX = b"k8s:enc:secretbox:v1:rewrite-key:"
CONFIG_DIR = "/etc/kubernetes/saf-rewrite-encryption"
CONFIG_PATH = f"{CONFIG_DIR}/provider.json"


def observe(args, lab, payload=None):
    """Return transient command output without passing it to Lab.command/logs."""
    try:
        result = subprocess.run(args, input=payload, env=lab.env, text=True,
                                capture_output=True, timeout=40)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("The isolated rewrite probe could not complete")
    if result.returncode:
        lab.block(f"The isolated {args[0]} rewrite probe failed without retaining output")
    return result.stdout


def encryption_config(key=None):
    if key is None:
        providers = [{"identity": {}}]
    else:
        providers = [
            {"secretbox": {"keys": [{"name": "rewrite-key", "secret": key}]}},
            {"identity": {}},  # retain read compatibility during this bounded probe
        ]
    return json.dumps({
        "apiVersion": "apiserver.config.k8s.io/v1",
        "kind": "EncryptionConfiguration",
        "resources": [{"resources": ["secrets"], "providers": providers}],
    })


def write_config(directory, contents):
    """Atomically replace the mounted file; key-bearing file stays mode 0600."""
    destination = directory / "provider.json"
    replacement = directory / f"provider.{secrets.token_hex(6)}.next"
    descriptor = os.open(replacement, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())
    replacement.replace(destination)


def kind_configuration(directory):
    return f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(directory))}
    containerPath: {CONFIG_DIR}
    readOnly: true
kubeadmConfigPatches:
- |
  kind: ClusterConfiguration
  apiVersion: kubeadm.k8s.io/v1beta4
  apiServer:
    extraArgs:
    - name: encryption-provider-config
      value: {CONFIG_PATH}
    - name: encryption-provider-config-automatic-reload
      value: "true"
    extraVolumes:
    - name: saf-rewrite-encryption
      hostPath: {CONFIG_DIR}
      mountPath: {CONFIG_DIR}
      readOnly: true
      pathType: Directory
"""


def kubectl(kubeconfig, cluster):
    return ["kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
            "--namespace", NAMESPACE, "--request-timeout=20s"]


def exact_storage(lab, kubeconfig, cluster):
    exact_key = f"/registry/secrets/{NAMESPACE}/{NAME}"
    command = [*kubectl(kubeconfig, cluster), "-n", "kube-system", "exec",
               f"etcd-{cluster}-control-plane", "-c", "etcd", "--",
               "etcdctl", "--endpoints=https://127.0.0.1:2379",
               "--cacert=/etc/kubernetes/pki/etcd/ca.crt",
               "--cert=/etc/kubernetes/pki/etcd/server.crt",
               "--key=/etc/kubernetes/pki/etcd/server.key", "get", exact_key,
               "--write-out=json"]
    # Raw etcd response exists only transiently in this process; never log or save it.
    response = observe(command, lab)
    rows = json.loads(response).get("kvs", [])
    if len(rows) != 1 or base64.b64decode(rows[0]["key"]).decode() != exact_key:
        lab.block("The store did not return exactly the owned synthetic Secret key")
    raw = base64.b64decode(rows[0]["value"], validate=True)
    summary = {
        "exact_key": exact_key,
        "secretbox_prefix": raw.startswith(PREFIX),
        "marker_present": MARKER.encode() in raw,
    }
    # Byte equality is checked with a transient digest; neither digest nor value
    # is included in the evidence receipt.
    return summary, hashlib.sha256(raw).digest()


def secret_read(lab, kubeconfig, cluster):
    response = observe([*kubectl(kubeconfig, cluster), "get", f"secret/{NAME}", "-o", "json"], lab)
    obj = json.loads(response)
    return (base64.b64decode(obj.get("data", {}).get("fixture", ""), validate=True).decode()
            == MARKER and obj.get("metadata", {}).get("annotations", {}).get(ANNOTATION) == MARKER)


@contextmanager
def rewrite_profile(lab):
    cluster = f"{lab.cluster}-rewrite"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block("Case-owned rewrite profile already exists")
    with tempfile.TemporaryDirectory(prefix="saf-encryption-rewrite-") as work:
        root = Path(work).resolve()
        mounted = root / "encryption"
        mounted.mkdir(mode=0o700)
        write_config(mounted, encryption_config())
        kubeconfig = root / "kubeconfig"
        kind_config = root / "kind.yaml"
        kind_config.write_text(kind_configuration(mounted))
        try:
            lab.command("kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                        "--config", str(kind_config), "--kubeconfig", str(kubeconfig),
                        "--wait", "90s", timeout=480)
            observe([*kubectl(kubeconfig, cluster), "create", "namespace", NAMESPACE], lab)
            yield cluster, kubeconfig, mounted
        finally:
            result = lab.command("kind", "delete", "cluster", "--name", cluster,
                                 "--kubeconfig", str(kubeconfig), timeout=90, allow_failure=True)
            if result.returncode:
                lab.block("Could not confirm the case-owned rewrite profile was deleted")


def successful_reload_timestamp(lab, command):
    metric = "apiserver_encryption_config_controller_automatic_reload_last_timestamp_seconds"
    output = observe([*command, "get", "--raw=/metrics"], lab)
    regex = re.compile(r'^' + metric + r'\{([^}]+)\}\s+(\S+)$', re.M)
    samples = [float(number) for labels, number in regex.findall(output)
               if 'status="success"' in labels]
    if len(samples) > 1:
        lab.block("Expected one owned API-server reload metric series")
    return samples[0] if samples else 0


def run_rewrite(lab):
    """Compare the stored record before and after the exact synthetic write."""
    with rewrite_profile(lab) as (cluster, kubeconfig, mounted):
        command = kubectl(kubeconfig, cluster)
        body = {
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": NAME, "annotations": {ANNOTATION: MARKER}},
            "type": "Opaque",
            "data": {"fixture": base64.b64encode(MARKER.encode()).decode()},
        }
        observe([*command, "create", "-f", "-", "-o", "name"], lab, json.dumps(body))

        baseline, baseline_digest = exact_storage(lab, kubeconfig, cluster)
        lab.check("red", "The exact pre-change synthetic Secret is plaintext",
                  baseline["marker_present"] and not baseline["secretbox_prefix"], baseline)
        lab.check("positive", "The original synthetic Secret is API-readable before the change",
                  secret_read(lab, kubeconfig, cluster), True)

        previous_reload = successful_reload_timestamp(lab, command)
        ephemeral_key = base64.b64encode(secrets.token_bytes(32)).decode()
        write_config(mounted, encryption_config(ephemeral_key))
        deadline = time.monotonic() + 95
        while time.monotonic() < deadline:
            latest_reload = successful_reload_timestamp(lab, command)
            if latest_reload > previous_reload:
                break
            time.sleep(3)
        else:
            lab.block("The owned API server did not report a successful encryption configuration reload")
        lab.check("positive", "The live API server reports a successful reload of the new provider configuration",
                  latest_reload > previous_reload, {"native_reload_observed": latest_reload > previous_reload})
        # Configuration change alone must not rewrite the existing etcd record.
        unchanged, unchanged_digest = exact_storage(lab, kubeconfig, cluster)
        lab.check("red", "Changing provider order alone leaves the exact old record unchanged",
                  unchanged_digest == baseline_digest and unchanged == baseline, unchanged)

        # The changed annotation forces one real write to the exact synthetic key.
        observe([*command, "annotate", f"secret/{NAME}",
                 "saf-k8s.example/rewrite=approved", "--overwrite"], lab)
        rewritten, _ = exact_storage(lab, kubeconfig, cluster)
        lab.check("green", "The API update rewrites only the exact synthetic Secret as ciphertext",
                  rewritten["secretbox_prefix"] and not rewritten["marker_present"], rewritten)
        lab.check("positive", "The rewritten Secret remains readable through the authorized API",
                  secret_read(lab, kubeconfig, cluster), True)
