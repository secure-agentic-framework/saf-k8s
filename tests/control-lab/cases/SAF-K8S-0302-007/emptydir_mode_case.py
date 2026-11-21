"""Compare requested and effective emptyDir mode with v1.37 gate skew."""
from contextlib import contextmanager
import json
from pathlib import Path
import runpy
import tempfile

from fixtures import container, pod


HERE = Path(__file__).parent
BASE = runpy.run_path(str(HERE / "case.py"))
NODE_IMAGE = (
    "kindest/node:v1.37.0@sha256:"
    "a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
)
SCOPE = (
    BASE["SCOPE"] + " The report's top-level version and image describe the v1.36.1 "
    "base cluster. Supplemental Linux disk-backed emptyDir profiles use v1.37.0. "
    "Compare matching and mismatched API-server and kubelet feature gates, then "
    "verify fsGroup on the enabled node."
)
NAMESPACE = "saf-emptydir-mode"
SCRATCH_GROUP = 2000
GATE = "EmptyDirVolumeMode"


@contextmanager
def kind_profile(lab, suffix, fixture):
    cluster = f"{lab.cluster}-{suffix}"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block(f"Case-owned cluster already exists: {cluster}")
    with tempfile.TemporaryDirectory(prefix="saf-emptydir-") as workspace:
        kubeconfig = Path(workspace) / "kubeconfig"

        def kube(*args, timeout=40, **kwargs):
            return lab.command(
                "kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
                "-n", NAMESPACE, f"--request-timeout={timeout - 5}s", *args,
                timeout=timeout, **kwargs,
            )

        try:
            lab.command(
                "kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                "--config", str(HERE / fixture), "--kubeconfig", str(kubeconfig),
                "--wait", "90s", timeout=480,
            )
            kube("create", "namespace", NAMESPACE)
            kube("wait", "--for=create", "serviceaccount/default", "--timeout=30s")
            yield cluster, kube
        finally:
            result = lab.command(
                "kind", "delete", "cluster", "--name", cluster, "--kubeconfig",
                str(kubeconfig), timeout=90, allow_failure=True,
            )
            if result.returncode:
                lab.block(f"Could not confirm cleanup of the {suffix} cluster")


def record_profile(lab, kube, cluster, *, api_gate, worker_gate):
    server = json.loads(kube("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    nodes = json.loads(kube("get", "nodes", "-o", "json").stdout)["items"]
    versions = {node["metadata"]["name"]: node["status"]["nodeInfo"]["kubeletVersion"]
                for node in nodes}
    roles = ("control-plane", "worker")
    observed = {role: versions.get(f"{cluster}-{role}") for role in roles}
    evidence = {
        "server_version": server, "kubelet_versions": observed, "node_image": NODE_IMAGE,
        "kind_version": lab.command("kind", "version").stdout.strip(),
        "configured_gates": {
            "kube-apiserver": {GATE: api_gate},
            "kubelet": {"control-plane": {GATE: True}, "worker": {GATE: worker_gate}},
        },
    }
    lab.check("positive", f"Supplemental profile records v1.37.0 versions and configured gates (API {api_gate}, worker {worker_gate})",
              server == "v1.37.0" and len(versions) == 2
              and observed == dict.fromkeys(roles, server), evidence)


def pod_request(name, node, mode, fs_group):
    worker = container(
        "probe", volumeMounts=[{"name": "scratch", "mountPath": "/scratch"}],
    )
    scratch = {} if mode is None else {"mode": mode}
    security = {} if fs_group is None else {"fsGroup": fs_group}
    return pod(
        name, [worker], nodeName=node, os={"name": "linux"},
        automountServiceAccountToken=False, securityContext=security,
        volumes=[{"name": "scratch", "emptyDir": scratch}],
    )


def observe(lab, kube, name, node, *, mode=None, fs_group=None):
    request = pod_request(name, node, mode, fs_group)
    created = json.loads(kube("create", "-f", "-", "-o", "json",
                              payload=json.dumps(request)).stdout)
    stored = json.loads(kube("get", "pod", name, "-o", "json").stdout)
    volume = stored["spec"]["volumes"][0]["emptyDir"]
    created_volume = created["spec"]["volumes"][0]["emptyDir"]
    if stored["spec"]["nodeName"] != node or stored["spec"]["os"]["name"] != "linux":
        lab.block(f"The stored Pod for {name} is outside its intended Linux node")
    kube("wait", f"pod/{name}", "--for=condition=Ready", "--timeout=80s", timeout=90)
    script = (
        "set -eu; stat -c '%a:%g' /scratch; id -u; "
        "if touch /scratch/synthetic-marker >/dev/null 2>&1; "
        "then echo writable; else echo denied; fi"
    )
    value, uid, write = kube("exec", f"pod/{name}", "--", "sh", "-c", script).stdout.splitlines()
    if uid != "65534":
        lab.block("The volume fixture must use the intended nonroot UID")
    permissions, group = value.split(":")
    return {
        "create_mode": formatted_mode(created_volume.get("mode")),
        "stored_mode": formatted_mode(volume.get("mode")),
        "mounted": permissions, "group": int(group), "write": write,
    }


def formatted_mode(mode):
    return None if mode is None else format(mode, "o")


def run(lab):
    BASE["run"](lab)
    with kind_profile(lab, "volume-mode", "emptydir-mode-kind.yaml") as (cluster, kube):
        record_profile(lab, kube, cluster, api_gate=True, worker_gate=False)
        enabled, disabled = f"{cluster}-control-plane", f"{cluster}-worker"

        default = observe(lab, kube, "implicit-mode", enabled)
        default_result = {"create_mode": None, "stored_mode": None, "mounted": "777",
                          "group": 0, "write": "writable"}
        lab.check("red", "An implicit disk emptyDir is writable at the default mode",
                  default == default_result, default)
        skew = observe(lab, kube, "skewed-mode", disabled, mode=0o700)
        lab.check("red", "The API retains 0700 when the worker ignores it and mounts 0777",
                  skew == {**default_result, "create_mode": "700", "stored_mode": "700"}, skew)

        restricted = observe(lab, kube, "restricted-mode", enabled, mode=0o700)
        restricted_result = {"create_mode": "700", "stored_mode": "700", "mounted": "700",
                             "group": 0, "write": "denied"}
        lab.check("green", "The enabled kubelet mounts 0700 and denies an unrelated nonroot writer",
                  restricted == restricted_result, restricted)
        group_owned = observe(lab, kube, "group-mode", enabled, mode=0o700, fs_group=SCRATCH_GROUP)
        lab.check("positive", "fsGroup changes effective mode and permits the approved group to write",
                  group_owned == {**restricted_result, "mounted": "2770", "group": SCRATCH_GROUP,
                                  "write": "writable"}, group_owned)

        bad_mode = pod_request("invalid-mode", enabled, 0o2000, None)
        result = kube("create", "-f", "-", "--dry-run=server", payload=json.dumps(bad_mode),
                      allow_failure=True)
        names_field = "emptyDir.mode" in result.stderr
        lab.check("green", "The API validates explicit mode within its supported bit range",
                  result.returncode != 0 and names_field, names_field)

    with kind_profile(lab, "api-off", "emptydir-api-off-kind.yaml") as (cluster, kube):
        record_profile(lab, kube, cluster, api_gate=False, worker_gate=True)
        pruned = observe(lab, kube, "api-off-mode", f"{cluster}-worker", mode=0o700)
        lab.check("green", "The API gate prunes requested 0700 before an enabled kubelet mounts the Pod",
                  pruned == default_result, pruned)
