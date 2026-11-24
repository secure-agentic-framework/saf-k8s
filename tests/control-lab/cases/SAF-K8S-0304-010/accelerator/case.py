"""Exercise conditional declarations and kubelet allocation using synthetic devices."""
import json
from pathlib import Path
import time

from fixtures import BUSYBOX_IMAGE

HERE = Path(__file__).resolve().parent
NS = "saf-lab-0304-010-accelerator"
RESOURCE = "example.com/resource"
POLICY = "saf-lab-0304-010-conditional-accelerator"
PLUGIN = "saf-sample-device-plugin"
DENIAL = "enrolled Pods must declare exactly one example.com/resource"


def pod(name, *, enrolled=False, device=None, limits_only=False):
    limits = {"cpu": "100m", "memory": "32Mi", "ephemeral-storage": "64Mi"}
    requests = {"cpu": "10m", "memory": "16Mi", "ephemeral-storage": "16Mi"}
    if device:
        key, amount = device
        limits[key] = amount
        if not limits_only:
            requests[key] = amount
    labels = {"saf.example.com/accelerator-required": "true"} if enrolled else {}
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": NS, "labels": labels},
            "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never", "containers": [{
                "name": "workload", "image": BUSYBOX_IMAGE, "command": ["sh", "-c", "sleep 3600"],
                "resources": {"requests": requests, "limits": limits},
                "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
            }]}}


def submit(lab, obj, *, dry_run=False):
    flags = ("--dry-run=server",) if dry_run else ()
    return lab.kubectl("-n", NS, "create", "-f", "-", "-o", "json", *flags,
                       payload=json.dumps(obj), allow_failure=True)


def json_resource(lab, *arguments):
    return json.loads(lab.kubectl(*arguments, "-o", "json").stdout)


def wait_for(lab, title, probe, timeout=100):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = probe()
        if observed:
            return observed
        time.sleep(1)
    lab.block(f"Timed out waiting for {title}")


def node_capacity(lab):
    nodes = json_resource(lab, "get", "nodes")["items"]
    matched = [node for node in nodes if node["status"]["allocatable"].get(RESOURCE) == "2"]
    if len(matched) == len(nodes) == 1:
        return matched[0]
    return None


def denied(result):
    return result.returncode != 0 and POLICY in result.stderr and DENIAL in result.stderr


def markers(lab, name):
    result = lab.kubectl("-n", NS, "exec", f"pod/{name}", "--",
                         "sh", "-c", "for f in /tmp/Dev-*; do if [ -f \"$f\" ]; then basename \"$f\"; fi; done")
    return sorted(result.stdout.split())


def run(lab):
    lab.kubectl("create", "namespace", NS)
    lab.kubectl("-n", "kube-system", "apply", "-f", str(HERE / "device-plugin.yaml"))
    lab.kubectl("-n", "kube-system", "rollout", "status", f"daemonset/{PLUGIN}",
                "--timeout=90s", timeout=100)
    node = wait_for(lab, "two allocatable tokens from the synthetic kubelet plugin", lambda: node_capacity(lab))
    lab.check("positive", "One fixture node advertises exactly two synthetic device-plugin units",
              node["status"]["capacity"].get(RESOURCE) == "2",
              {"capacity": node["status"]["capacity"].get(RESOURCE),
               "allocatable": node["status"]["allocatable"].get(RESOURCE)})

    defaulted = submit(lab, pod("device-limits-only", device=(RESOURCE, "1"), limits_only=True), dry_run=True)
    requests = json.loads(defaulted.stdout)["spec"]["containers"][0]["resources"]["requests"] if defaulted.returncode == 0 else {}
    lab.check("positive", "Kubernetes defaults the synthetic device request from its explicit limit",
              requests.get(RESOURCE) == "1", {"defaulted_request": requests.get(RESOURCE)})

    invalid = pod("unequal")
    r = invalid["spec"]["containers"][0]["resources"]
    r["requests"][RESOURCE], r["limits"][RESOURCE] = "1", "2"
    rejected = submit(lab, invalid, dry_run=True)
    lab.check("positive", "Native API validation rejects unequal extended-resource values",
              rejected.returncode != 0 and RESOURCE in rejected.stderr and "invalid" in rejected.stderr.lower(),
              {"unequal_quantity_rejected": rejected.returncode != 0})

    variants = {"missing": pod("missing", enrolled=True),
                "wrong": pod("wrong", enrolled=True, device=("example.com/other", "1"))}
    baseline = {name: submit(lab, value, dry_run=True).returncode == 0 for name,value in variants.items()}
    lab.check("red", "Before enforcing the enrollment rule, both fixture declaration gaps are admitted",
              all(baseline.values()), {"admitted_before_policy": baseline})
    lab.kubectl("apply", "-f", str(HERE / "conditional-policy.yaml"))
    wait_for(lab, "named declaration policy evaluation",
             lambda: denied(submit(lab, variants["missing"], dry_run=True)), timeout=32)
    refused = {name: denied(submit(lab, value, dry_run=True)) for name,value in variants.items()}
    lab.check("green", "The named conditional policy rejects both missing and wrong extended-resource keys",
              all(refused.values()), {"rejected_by_policy": refused})

    first, second, ordinary = "accelerator-one", "accelerator-two", "cpu-only"
    for name in (first, second, ordinary):
        selected = name != ordinary
        obj = pod(name, enrolled=selected, device=(RESOURCE, "1") if selected else None)
        lab.kubectl("-n", NS, "create", "-f", "-", payload=json.dumps(obj))
        lab.kubectl("-n", NS, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=85s", timeout=95)
    update = lab.kubectl(
        "-n", NS, "patch", "pod", ordinary, "--type=merge",
        "--patch", json.dumps({"metadata": {"labels": {"saf.example.com/accelerator-required": "true"}}}),
        "--dry-run=server", "-o", "json", allow_failure=True,
    )
    lab.check("green", "Conditional policy rejects enrolling a CPU-only Pod by label update",
              denied(update), {"denied_by_conditional_policy": denied(update)})
    allocated = {name: markers(lab, name) for name in (first, second, ordinary)}
    both = sorted([*allocated[first], *allocated[second]])
    lab.check("green", "Separate running Pods see distinct files mounted by the kubelet Allocate response",
              len(allocated[first]) == len(allocated[second]) == 1 and both == ["Dev-1", "Dev-2"],
              {"allocated_device_markers": both, "one_marker_per_enrolled_pod": len(allocated[first]) == len(allocated[second]) == 1})
    lab.check("positive", "The CPU-only control runs with no synthetic device mount",
              allocated[ordinary] == [], {"cpu_only_has_no_device_marker": allocated[ordinary] == []})

    exhausted = "accelerator-exhausted"
    lab.kubectl("-n", NS, "create", "-f", "-",
                payload=json.dumps(pod(exhausted, enrolled=True, device=(RESOURCE, "1"))))
    def unscheduled():
        item = json_resource(lab, "-n", NS, "get", "pod", exhausted)
        matches = [c for c in item["status"].get("conditions", []) if c.get("type") == "PodScheduled"
                   and c.get("status") == "False" and c.get("reason") == "Unschedulable"
                   and f"Insufficient {RESOURCE}" in c.get("message", "")]
        return item if matches and not item["spec"].get("nodeName") else None
    status = wait_for(lab, "specific scheduler exhaustion condition", unscheduled)
    lab.check("green", "A third enrolled request remains unscheduled with the exact insufficient-device reason",
              status["status"]["phase"] == "Pending", {"pending": status["status"]["phase"] == "Pending",
                                                       "insufficient_resource": RESOURCE})
    (lab.evidence / "synthetic-device-allocation.json").write_text(json.dumps(
        {"allocations": allocated, "scheduler_conditions": status["status"]["conditions"]}, indent=2) + "\n")
