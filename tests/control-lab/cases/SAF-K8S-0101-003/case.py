"""Observe encryption of two exact synthetic API resource keys."""
import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import runpy
import secrets
import subprocess
import tempfile

from fixtures import BUSYBOX_IMAGE
from lab import NAMESPACE, NODE_IMAGE


SCOPE = (
    "Kubernetes v1.36.1 kind. Compare stock storage and two Secretbox configuration "
    "profiles using the core-group and all-group wildcards. Inspect only an exact "
    "synthetic Secret key and an exact synthetic apps Deployment key. A separate owned profile verifies a native provider reload and the rewrite of one synthetic Secret."
)
MARKER = "saf-k8s-public-synthetic-marker-0101-003"
NAME = "saf-encryption-probe"
ANNOTATION = "saf-k8s.example/marker"
PREFIX = b"k8s:enc:secretbox:v1:"
CONFIG_DESTINATION = "/etc/kubernetes/saf-encryption-config.yaml"


def observe_command(lab, args, payload=None):
    # Credentials, encryption config and storage values are never sent to Lab.command.
    try:
        result = subprocess.run(args, input=payload, env=lab.env, text=True,
                                capture_output=True, timeout=40)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("An isolated encryption probe could not complete")
    if result.returncode:
        lab.block(f"An isolated {args[0]} encryption probe failed without retaining output")
    return result.stdout


def fixtures():
    secret = {
        "apiVersion": "v1", "kind": "Secret", "metadata": {"name": NAME}, "type": "Opaque",
        "data": {"fixture": base64.b64encode(MARKER.encode()).decode()},
    }
    deployment = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": NAME, "annotations": {ANNOTATION: MARKER}},
        "spec": {
            "replicas": 0, "selector": {"matchLabels": {"app": NAME}},
            "template": {
                "metadata": {"labels": {"app": NAME}},
                "spec": {"automountServiceAccountToken": False,
                         "containers": [{"name": "fixture", "image": BUSYBOX_IMAGE}]},
            },
        },
    }
    return (("secrets", secret), ("deployments", deployment))


def check_storage(lab, kubeconfig, cluster, wildcard):
    kubectl = ["kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
               "--namespace", NAMESPACE, "--request-timeout=20s"]
    for resource, fixture in fixtures():
        observe_command(lab, [*kubectl, "create", "-f", "-", "-o", "name"], json.dumps(fixture))
        exact_key = f"/registry/{resource}/{NAMESPACE}/{NAME}"
        response = observe_command(lab, [
            *kubectl, "-n", "kube-system", "exec", f"etcd-{cluster}-control-plane", "-c", "etcd", "--",
            "etcdctl", "--endpoints=https://127.0.0.1:2379",
            "--cacert=/etc/kubernetes/pki/etcd/ca.crt",
            "--cert=/etc/kubernetes/pki/etcd/server.crt",
            "--key=/etc/kubernetes/pki/etcd/server.key", "get", exact_key, "--write-out=json",
        ])
        rows = json.loads(response).get("kvs", [])
        if len(rows) != 1 or base64.b64decode(rows[0]["key"]).decode() != exact_key:
            lab.block("The store did not return exactly the synthetic fixture key")
        raw = base64.b64decode(rows[0]["value"], validate=True)
        actual = {"secretbox_prefix": raw.startswith(PREFIX),
                  "marker_present": MARKER.encode() in raw}
        encrypts = wildcard == "*.*" or (wildcard == "*." and resource == "secrets")
        label = wildcard or "stock"
        lab.check("green" if encrypts else "red", f"{label} storage for the exact {resource} fixture",
                  actual == {"secretbox_prefix": encrypts, "marker_present": not encrypts}, actual)
        obj = json.loads(observe_command(lab, [*kubectl, "get", f"{resource}/{NAME}", "-o", "json"]))
        value = (base64.b64decode(obj["data"]["fixture"]).decode() if resource == "secrets"
                 else obj["metadata"]["annotations"][ANNOTATION])
        lab.check("positive", f"{label} still permits an authorized read of the {resource} fixture",
                  value == MARKER, value == MARKER)


def kind_configuration(config):
    return f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(config))}
    containerPath: {CONFIG_DESTINATION}
    readOnly: true
kubeadmConfigPatches:
- |
  kind: ClusterConfiguration
  apiVersion: kubeadm.k8s.io/v1beta4
  apiServer:
    extraArgs:
    - name: encryption-provider-config
      value: {CONFIG_DESTINATION}
    extraVolumes:
    - name: saf-encryption-config
      hostPath: {CONFIG_DESTINATION}
      mountPath: {CONFIG_DESTINATION}
      readOnly: true
      pathType: File
"""


@contextmanager
def encrypted_profile(lab, suffix, wildcard):
    cluster = f"{lab.cluster}-{suffix}"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block("Case-owned encrypted profile already exists")
    with tempfile.TemporaryDirectory(prefix="saf-encryption-") as work:
        root = Path(work).resolve()
        kubeconfig = root / "kubeconfig"
        config = root / "encryption.yaml"
        template = Path(__file__).with_name("encryption-config.yaml").read_text()
        key = base64.b64encode(secrets.token_bytes(32)).decode()
        descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(template.replace("__RESOURCE_WILDCARD__", wildcard)
                         .replace("__EPHEMERAL_BASE64_KEY__", key))
        kind_config = root / "kind.yaml"
        kind_config.write_text(kind_configuration(config))
        try:
            lab.command("kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                        "--config", str(kind_config), "--kubeconfig", str(kubeconfig),
                        "--wait", "90s", timeout=480)
            observe_command(lab, ["kubectl", "--kubeconfig", str(kubeconfig), "--context",
                                  f"kind-{cluster}", "create", "namespace", NAMESPACE])
            yield cluster, kubeconfig
        finally:
            result = lab.command("kind", "delete", "cluster", "--name", cluster, "--kubeconfig",
                                 str(kubeconfig), timeout=90, allow_failure=True)
            if result.returncode:
                lab.block("Could not confirm the case-owned encryption profile was deleted")


def run(lab):
    check_storage(lab, lab.kubeconfig, lab.cluster, None)
    for suffix, wildcard in (("core", "*."), ("all", "*.*")):
        with encrypted_profile(lab, suffix, wildcard) as (cluster, kubeconfig):
            check_storage(lab, kubeconfig, cluster, wildcard)

    rewrite = runpy.run_path(str(Path(__file__).with_name("rewrite_fixture.py")))
    rewrite["run_rewrite"](lab)
