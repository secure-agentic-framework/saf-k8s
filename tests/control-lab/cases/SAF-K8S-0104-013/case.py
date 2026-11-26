"""Upgrade an owned kubeadm control plane and verify retained state and workload recovery."""

import json
from pathlib import Path
import stat
import tempfile
import time

SCOPE = ("Actual disposable kubeadm minor upgrade and kubelet replacement with a retained public marker. "
         "The separately exercised rollback affects only a fixture Deployment.")
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
TARGET_IMAGE = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
BASE = "v1.36.1"
TARGET = "v1.37.0"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
NAME = "fixture-upgrade-marker"
PUBLIC = "fixture public retained upgrade record"
POD_SELECTOR = f"app={NAME}"
NEW_BIN = "/usr/local/lib/saf-upgrade-fixture"
KUBEADM = f"{NEW_BIN}/kubeadm"


def node(lab, *args, timeout=45, allow_failure=False):
    return lab.command("docker", "exec", f"{lab.cluster}-control-plane", *args, timeout=timeout,
                       allow_failure=allow_failure)


def setup(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                "immutable": True, "data": {"marker": PUBLIC}})
    selector = {"app": NAME}
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": NAME}, "spec": {
        "replicas": 1, "progressDeadlineSeconds": 25, "selector": {"matchLabels": selector},
        "template": {"metadata": {"labels": selector}, "spec": {
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "unit", "image": IMAGE,
                "command": ["python", "-c", "import time; time.sleep(420)"],
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                              "limits": {"cpu": "100m", "memory": "48Mi"}},
                "env": [{"name": "RELEASE", "value": "approved"}],
                "volumeMounts": [{"name": "marker", "mountPath": "/fixture", "readOnly": True}],
                "readinessProbe": {"exec": {"command": ["python", "-c",
                    "import os; import sys; sys.exit(os.environ['RELEASE'] != 'approved')"]},
                    "periodSeconds": 2}}],
            "volumes": [{"name": "marker", "configMap": {"name": NAME}}],
        }},
    }})
    lab.kubectl("rollout", "status", f"deployment/{NAME}", "--timeout=75s", timeout=85)


def stage_binaries(lab):
    container = lab.command("docker", "create", "--network=none", TARGET_IMAGE).stdout.strip()
    if len(container) != 64 or any(char not in "0123456789abcdef" for char in container):
        lab.block("Expected a single newly created image extraction container")
    node(lab, "mkdir", "-m", "0700", NEW_BIN)
    try:
        with tempfile.TemporaryDirectory(dir=lab.kubeconfig.parent, prefix="target-binaries-") as tmp:
            for name in ("kubeadm", "kubelet", "kubectl"):
                binary = Path(tmp) / name
                lab.command("docker", "cp", f"{container}:/usr/bin/{name}", str(binary), timeout=90)
                binary.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                lab.command("docker", "cp", str(binary), f"{lab.cluster}-control-plane:{NEW_BIN}/{name}", timeout=90)
    finally:
        lab.command("docker", "rm", container)
    current = node(lab, KUBEADM, "version", "-o", "short").stdout.strip()
    kubelet = node(lab, f"{NEW_BIN}/kubelet", "--version").stdout.strip()
    if current != TARGET or kubelet != f"Kubernetes {TARGET}":
        lab.block("The extracted tools did not match the explicitly selected Kubernetes version")


def versions(lab):
    server = json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    item, = nodes
    return {"apiserver": server, "kubelet": item["status"]["nodeInfo"]["kubeletVersion"]}


def marker(lab):
    result = lab.kubectl("exec", "deployment/" + NAME, "--", "cat", "/fixture/marker",
                         allow_failure=True, timeout=15)
    return result.returncode == 0 and result.stdout.strip() == PUBLIC



def on_target(lab, *args, **kwargs):
    return node(lab, f"{NEW_BIN}/kubectl", "--kubeconfig=/etc/kubernetes/admin.conf",
                "--namespace=saf-test", "--request-timeout=8s", *args, **kwargs)


def await_revision(lab, accepted):
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        response = on_target(lab, "get", "deployment", NAME, "-o", "json", allow_failure=True)
        if response.returncode == 0:
            state = json.loads(response.stdout)
            status = state.get("status", {})
            acknowledged = status.get("observedGeneration") == state["metadata"]["generation"]
            if acknowledged and accepted is True:
                if status.get("updatedReplicas") == status.get("readyReplicas") == status.get("availableReplicas") == 1:
                    return True
            elif acknowledged and any(item["type"] == "Progressing" and item.get("reason") == "ProgressDeadlineExceeded"
                                      for item in status.get("conditions", [])):
                return True
        time.sleep(1)
    for component in ("kube-apiserver", "kube-controller-manager", "kube-scheduler"):
        on_target(lab, "-n", "kube-system", "logs", f"pod/{component}-{lab.cluster}-control-plane",
                  "--tail=35", allow_failure=True, timeout=15)
    return False

def apply_version(lab, base, target):
    upgraded = node(lab, KUBEADM, "upgrade", "apply", target, "--yes", "--certificate-renewal=false",
                    "--etcd-upgrade=false", timeout=260)
    intermediate = versions(lab)
    ordered = intermediate == {"apiserver": target, "kubelet": base}
    if not ordered:
        lab.block("The control-plane transition must precede the fixture kubelet binary transition")
    node(lab, "install", "-m", "0755", f"{NEW_BIN}/kubelet", "/usr/bin/kubelet.saf-next")
    node(lab, "mv", "/usr/bin/kubelet.saf-next", "/usr/bin/kubelet")
    node(lab, "systemctl", "restart", "kubelet")
    expected = {"apiserver": target, "kubelet": target}
    deadline = time.monotonic() + 70
    final = versions(lab)
    while final != expected and time.monotonic() < deadline:
        time.sleep(1)
        final = versions(lab)
    lab.kubectl("wait", "--for=condition=Ready", "node/" + lab.cluster + "-control-plane",
                "--timeout=60s", timeout=70)
    return ordered, final, upgraded.returncode


def exercise_workload_recovery(lab, expected):
    control = on_target(lab, "get", "deployment", NAME, "-o", "json", allow_failure=True)
    if control.returncode:
        lab.block("The target-version API client could not read the reviewed workload")
    original = json.loads(control.stdout)["spec"]["template"]
    on_target(lab, "set", "env", f"deployment/{NAME}", "RELEASE=fixture-rejected")
    rejected = await_revision(lab, accepted=False)
    if not rejected:
        lab.block("The upgraded controller did not record the expected failed fixture rollout")
    on_target(lab, "patch", "deployment", NAME, "--type=json", "-p", json.dumps([
        {"op": "replace", "path": "/spec/template", "value": original},
    ]))
    recovered = await_revision(lab, accepted=True)
    state = json.loads(on_target(lab, "get", "deployment", NAME, "-o", "json").stdout)
    current = state["spec"]["template"]["spec"]["containers"][0]["env"]
    recovery = (recovered and current == [{"name": "RELEASE", "value": "approved"}]
                and marker(lab) and versions(lab) == expected)
    lab.check("positive", "Reapplying the reviewed workload template restores its readiness on the upgraded control plane",
              rejected and recovery, {"failed_rollout_exposed": rejected, "workload_recovery_verified": recovery})
    return rejected, recovery


def run(lab):
    setup(lab)
    baseline = versions(lab)
    stage_binaries(lab)
    plan = node(lab, KUBEADM, "upgrade", "plan", TARGET, timeout=100)
    accepted = BASE in plan.stdout and TARGET in plan.stdout
    initial = marker(lab)
    lab.check("red", "The control plane and kubelet start on the previous minor and the exact target is planned",
              baseline == {"apiserver": BASE, "kubelet": BASE} and accepted and initial,
              {**baseline, "explicit_target_planned": accepted, "preupgrade_marker": initial})

    ordered, final, upgrade_exit = apply_version(lab, BASE, TARGET)
    expected = {"apiserver": TARGET, "kubelet": TARGET}
    retained = marker(lab)
    lab.check("green", "The control plane upgrades first, followed by its kubelet, and the existing marker survives",
              final == expected and retained,
              {"control_plane_first": ordered, **final, "retained_marker": retained})

    rejected, recovery = exercise_workload_recovery(lab, expected)
    (lab.evidence / "kubeadm-upgrade-observations.json").write_text(json.dumps({
        "initial": baseline, "intermediate": intermediate, "final": final, "retained_marker": retained,
        "failed_rollout_observed": rejected, "workload_rollback_verified": recovery,
        "kubeadm_exit_code": upgrade_exit, "etcd_upgrade_tested": False,
        "control_plane_downgrade_or_restore_tested": False,
    }, indent=2) + "\n")
