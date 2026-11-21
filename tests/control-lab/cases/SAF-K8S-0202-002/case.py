"""Validate explicit RuntimeClass enforcement, node scheduling, and CRI handler choice."""
import json
from pathlib import Path
import re
import time

IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
NAMESPACE = "saf-test"
PROTECTED = "saf-k8s-0202-002.protected"
NODE_LABEL = "saf-k8s-0202-002.runtime-handler"
HANDLER = "saf-runc"
STATE_ROOT = "/run/saf-runtimeclass-runc/k8s.io"
DENIAL = "protected workloads must select RuntimeClass saf-runc"

SCOPE = (
    "One-node local kind cluster using the repository-pinned Kubernetes 1.36.1 "
    "node image and containerd CRI. A kind containerd config patch registers the "
    "explicit saf-runc handler as io.containerd.runc.v2; RuntimeClass scheduling "
    "selects the node labeled for that handler. A ValidatingAdmissionPolicy "
    "requires protected Pods to name that RuntimeClass. Tests use a digest-pinned, "
    "network-idle BusyBox fixture and observe the exact ready sandbox ID at the runc shim state root. "
    "This validates handler selection with runc. Stronger sandbox and GPU profiles require their own tests."
)


def pod(name, runtime_class=None):
    spec = {
        "restartPolicy": "Always",
        "automountServiceAccountToken": False,
        "containers": [{
            "name": "fixture",
            "image": IMAGE,
            "command": ["sh", "-c", "sleep 3600"],
            "securityContext": {
                "allowPrivilegeEscalation": False,
                "capabilities": {"drop": ["ALL"]},
                "runAsNonRoot": True,
                "runAsUser": 65534,
                "readOnlyRootFilesystem": True,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
        }],
    }
    if runtime_class is not None:
        spec["runtimeClassName"] = runtime_class
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "labels": {PROTECTED: "true"}},
        "spec": spec,
    }


def deployment():
    labels = {"app": "saf-0202-rollout", PROTECTED: "true"}
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "saf-0202-permitted-rollout"},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": labels["app"]}},
            "template": {
                "metadata": {"labels": labels},
                "spec": pod("template", HANDLER)["spec"],
            },
        },
    }


def crictl_sandbox(lab, pod_name):
    node = f"{lab.cluster}-control-plane"
    listed = json.loads(lab.command(
        "docker", "exec", node, "crictl", "pods", "-o", "json", timeout=30
    ).stdout)
    rows = listed.get("items", listed) if isinstance(listed, dict) else listed
    match = [row for row in rows
             if row.get("metadata", {}).get("name") == pod_name
             and row.get("metadata", {}).get("namespace") == NAMESPACE]
    if len(match) != 1:
        lab.block(f"CRI did not return exactly one sandbox for {pod_name}")
    row = match[0]
    sandbox = row.get("id", "")
    if not re.fullmatch(r"[a-f0-9]{64}", sandbox) or row.get("state") != "SANDBOX_READY":
        lab.block("CRI did not report the expected ready sandbox ID")
    present = lab.command("docker", "exec", node, "test", "-d", f"{STATE_ROOT}/{sandbox}",
                          allow_failure=True, timeout=10)
    if present.returncode not in (0, 1):
        lab.block("Could not measure the case-owned runtime's state root")
    return present.returncode == 0


def await_denial(lab, fixture):
    deadline = time.monotonic() + 30
    while True:
        response = lab.create(fixture, dry_run=True, allow_failure=True)
        if response.returncode and DENIAL in response.stderr:
            return True
        if response.returncode or time.monotonic() >= deadline:
            return False
        time.sleep(0.5)


def await_ready(lab, name):
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=90s",
                timeout=100)
    current = json.loads(lab.kubectl("get", f"pod/{name}", "-o", "json").stdout)
    return current


def run(lab):
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf-k8s-0202-002.case=enabled", "--overwrite")
    lab.create({
        "apiVersion": "node.k8s.io/v1",
        "kind": "RuntimeClass",
        "metadata": {"name": HANDLER},
        "handler": HANDLER,
        "scheduling": {"nodeSelector": {NODE_LABEL: HANDLER}},
    })

    # Red: the same protected fixture is admitted and runs with the node's
    # default runtime when no RuntimeClass is selected.
    baseline = pod("saf-0202-baseline")
    red = lab.create(baseline, dry_run=True, allow_failure=True)
    lab.check("red", "Unassigned protected workload reaches API admission before validation",
              red.returncode == 0, red.stderr.strip() or "server dry-run admitted")
    lab.create(baseline)
    running = await_ready(lab, baseline["metadata"]["name"])
    custom_state = crictl_sandbox(lab, baseline["metadata"]["name"])
    lab.check("red", "Ready baseline sandbox has no state under the explicit handler root",
              running["status"].get("phase") == "Running" and not custom_state,
              {"pod_running": running["status"].get("phase") == "Running",
               "custom_handler_state_exists": custom_state})

    lab.kubectl("delete", f"pod/{baseline['metadata']['name']}", "--wait=true", "--timeout=40s", timeout=50)
    lab.apply(Path(__file__).with_name("admission-policy.yaml"))
    denied = await_denial(lab, baseline)
    lab.check("green", "Admission denies protected workload without explicit RuntimeClass",
              denied, {"exact_policy_denial": denied})

    # Positive: an allowed Deployment rollout must land on the RuntimeClass
    # node and the CRI sandbox must report the named runtime handler.
    lab.create(deployment())
    rollout = lab.kubectl("rollout", "status", "deployment/saf-0202-permitted-rollout",
                          "--timeout=100s", timeout=110)
    pods = json.loads(lab.kubectl("get", "pods", "-l", "app=saf-0202-rollout",
                                  "-o", "json").stdout)["items"]
    if len(pods) != 1:
        lab.block("Permitted Deployment did not produce exactly one Pod")
    name = pods[0]["metadata"]["name"]
    current = await_ready(lab, name)
    selected_node = current["spec"].get("nodeName", "")
    if selected_node != f"{lab.cluster}-control-plane":
        lab.block("Permitted Pod did not reach the expected owned kind node")
    node = json.loads(lab.kubectl("get", "node", selected_node, "-o", "json").stdout)
    label = node["metadata"].get("labels", {}).get(NODE_LABEL)
    selector = current["spec"].get("nodeSelector", {}).get(NODE_LABEL)
    scheduled = (current["spec"].get("runtimeClassName") == HANDLER
                 and current["status"].get("phase") == "Running"
                 and selector == HANDLER and label == HANDLER)
    lab.check("positive", "RuntimeClass rollout runs Ready with the selector on its supported node",
              rollout.returncode == 0 and scheduled,
              {"pod_running": current["status"].get("phase") == "Running",
               "runtimeclass_selector_matches_node": selector == label == HANDLER})

    custom_state = crictl_sandbox(lab, name)
    lab.check("positive", "Native runc state confirms handler selection for the exact CRI sandbox",
              custom_state, {"custom_handler_state_exists": custom_state})
