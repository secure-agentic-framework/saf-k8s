"""Compare declared and mounted emptyDir mode with a v1.37 kubelet gate skew."""
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
    BASE["SCOPE"] + " Also compare Linux disk-backed emptyDir on Kubernetes v1.37.0 "
    "using two kubelets with opposite EmptyDirVolumeMode gates, then verify the "
    "effects of fsGroup on the enabled node."
)
NAMESPACE = "saf-emptydir-mode"
SCRATCH_GROUP = 2000


@contextmanager
def mixed_gate_profile(lab):
    cluster = f"{lab.cluster}-volume-mode"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block(f"Case-owned cluster already exists: {cluster}")
    with tempfile.TemporaryDirectory(prefix="saf-emptydir-mode-") as workspace:
        kubeconfig = Path(workspace) / "kubeconfig"
        try:
            lab.command(
                "kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                "--config", str(HERE / "emptydir-mode-kind.yaml"), "--kubeconfig",
                str(kubeconfig), "--wait", "90s", timeout=480,
            )
            yield cluster, kubeconfig
        finally:
            result = lab.command(
                "kind", "delete", "cluster", "--name", cluster, "--kubeconfig",
                str(kubeconfig), timeout=90, allow_failure=True,
            )
            if result.returncode:
                lab.block("Could not confirm cleanup of the mixed-gate cluster")


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
    volume = created["spec"]["volumes"][0]["emptyDir"]
    if volume.get("mode") != mode or created["spec"]["nodeName"] != node:
        lab.block(f"The API did not retain the requested mode and node for {name}")
    kube("wait", f"pod/{name}", "--for=condition=Ready", "--timeout=80s", timeout=90)
    script = (
        "set -eu; stat -c '%a:%g' /scratch; id -u; "
        "if touch /scratch/synthetic-marker >/dev/null 2>&1; "
        "then echo writable; else echo denied; fi"
    )
    value, uid, write = kube("exec", f"pod/{name}", "--", "sh", "-c", script).stdout.splitlines()
    if uid == "0":
        lab.block("The volume fixture must remain nonroot")
    permissions, group = value.split(":")
    return {"declared": None if mode is None else format(mode, "o"),
            "mounted": permissions, "group": int(group), "write": write}


def run(lab):
    BASE["run"](lab)
    with mixed_gate_profile(lab) as (cluster, kubeconfig):
        def kube(*args, timeout=40, **kwargs):
            return lab.command(
                "kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
                "-n", NAMESPACE, f"--request-timeout={timeout - 5}s", *args,
                timeout=timeout, **kwargs,
            )

        server = json.loads(kube("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
        nodes = json.loads(kube("get", "nodes", "-o", "json").stdout)["items"]
        kubelets = {node["metadata"]["name"]: node["status"]["nodeInfo"]["kubeletVersion"]
                    for node in nodes}
        enabled, disabled = f"{cluster}-control-plane", f"{cluster}-worker"
        lab.check("positive", "The separate API server and both kubelets run Kubernetes v1.37.0",
                  server == "v1.37.0" and kubelets == dict.fromkeys((enabled, disabled), server),
                  {"server": server, "kubelets": sorted(kubelets.values()), "image": NODE_IMAGE})
        kube("create", "namespace", NAMESPACE)
        kube("wait", "--for=create", "serviceaccount/default", "--timeout=30s")

        default = observe(lab, kube, "implicit-mode", enabled)
        lab.check("red", "An implicit disk emptyDir is writable at the default mode",
                  default == {"declared": None, "mounted": "777", "group": 0, "write": "writable"},
                  default)
        skew = observe(lab, kube, "skewed-mode", disabled, mode=0o700)
        lab.check("red", "The API retains 0700 when the worker ignores it and mounts 0777",
                  skew == {"declared": "700", "mounted": "777", "group": 0, "write": "writable"},
                  skew)

        restricted = observe(lab, kube, "restricted-mode", enabled, mode=0o700)
        lab.check("green", "The enabled kubelet mounts 0700 and denies an unrelated nonroot writer",
                  restricted == {"declared": "700", "mounted": "700", "group": 0,
                                 "write": "denied"}, restricted)
        group_owned = observe(lab, kube, "group-mode", enabled, mode=0o700, fs_group=SCRATCH_GROUP)
        lab.check("positive", "fsGroup changes effective mode and permits the approved group to write",
                  group_owned == {"declared": "700", "mounted": "2770", "group": SCRATCH_GROUP,
                                  "write": "writable"}, group_owned)

        bad_mode = pod_request("invalid-mode", enabled, 0o2000, None)
        result = kube("create", "-f", "-", "--dry-run=server", payload=json.dumps(bad_mode),
                      allow_failure=True)
        lab.check("green", "The API validates explicit mode within its supported bit range",
                  result.returncode != 0 and "emptyDir.mode" in result.stderr,
                  "emptyDir.mode" in result.stderr)
