"""Report QoS status for harmless Pods with small, pinned resource fixtures."""
import json
from pathlib import Path
import time

HERE = Path(__file__).parent
FIXTURES = json.loads((HERE / "fixtures.json").read_text())
CRITICAL = {"saf-k8s.example/qos-critical": "true"}
DENIAL = "Critical fixture requires equal positive CPU and memory requests and limits"
SCOPE = (
    "Kubernetes v1.36.1 Pod status classification with short-lived idle fixtures, "
    "including init and Pod-level CPU/memory resources, unequal ephemeral-storage, "
    "and the CPU quota on a Guaranteed container. A case-scoped ValidatingAdmissionPolicy "
    "tests critical and ordinary Pod CREATE requests. Kubelet eviction rankings are "
    "reviewed against first-party sources. Live eviction and production coverage remain separate."
)


def pod_for(fixture):
    containers = []
    for item in fixture["containers"]:
        containers.append({
            "name": item["name"],
            "image": FIXTURES["image"],
            "command": item["command"],
            "securityContext": FIXTURES["container_security_context"],
            **({"resources": item["resources"]} if "resources" in item else {}),
        })

    spec = {"restartPolicy": "Always", "containers": containers,
            "automountServiceAccountToken": False}
    if "initContainers" in fixture:
        spec["initContainers"] = [
            {
                "name": item["name"],
                "image": FIXTURES["image"],
                "command": item["command"],
                "securityContext": FIXTURES["container_security_context"],
                "resources": item["resources"],
            }
            for item in fixture["initContainers"]
        ]
    if "pod_resources" in fixture:
        spec["resources"] = fixture["pod_resources"]
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": fixture["name"], "namespace": "saf-test",
                     "labels": CRITICAL if fixture.get("critical") else {}},
        "spec": spec,
    }


def run(lab):
    for fixture in FIXTURES["pods"]:
        name = fixture["name"]
        lab.create(pod_for(fixture))
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=95s",
                    timeout=105)
        observed = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
        phase = observed.get("status", {}).get("phase")
        qos = observed.get("status", {}).get("qosClass")
        containers = observed.get("status", {}).get("containerStatuses", [])
        running = bool(containers) and all(
            status.get("ready") and status.get("state", {}).get("running") is not None
            for status in containers
        )
        lab.check(
            "red" if fixture.get("critical") else "positive",
            f"{name} reaches Running and reports QoS {fixture['expected_qos']}",
            phase == "Running" and running and qos == fixture["expected_qos"],
            {"phase": phase, "qosClass": qos, "containersRunningAndReady": running},
        )
        if name == "saf-0304-guaranteed":
            resources = observed["spec"]["containers"][0]["resources"]
            requested, limited = [resources[key]["ephemeral-storage"] for key in ("requests", "limits")]
            lab.check("positive", "Unequal ephemeral-storage limits do not change Guaranteed QoS",
                      requested == "8Mi" and limited == "16Mi" and qos == "Guaranteed",
                      {"ephemeral_storage_request": requested, "ephemeral_storage_limit": limited})
            quota, period = lab.kubectl("exec", f"pod/{name}", "--", "cat", "/sys/fs/cgroup/cpu.max").stdout.split()
            limited_cpu = quota.isdigit() and period.isdigit() and int(quota) > 0 and int(quota) * 10 == int(period)
            lab.check("positive", "The Guaranteed container has an active 100m CPU quota",
                      limited_cpu, {"quota_matches_cpu_limit": limited_cpu})

    lab.apply(HERE / "admission-policy.yaml")
    policy_probes = {fixture["name"]: pod_for(fixture) for fixture in FIXTURES["pods"]}
    bad = policy_probes["saf-0304-besteffort"]
    bad["metadata"]["name"] += "-policy"
    deadline = time.monotonic() + 25
    while True:
        result = lab.create(bad, dry_run=True, allow_failure=True)
        if (result.returncode and DENIAL in result.stderr) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("green", "The active policy rejects the same critical BestEffort Pod shape",
              result.returncode != 0 and DENIAL in result.stderr,
              {"expected_policy_denial": DENIAL in result.stderr})
    ordinary = {**bad, "metadata": {**bad["metadata"], "labels": {}}}
    approved = [("BestEffort", ordinary)]
    for key in ("saf-0304-guaranteed", "saf-0304-podlevel-guaranteed"):
        positive = policy_probes[key]
        positive["metadata"]["name"] += "-policy"
        positive["metadata"]["labels"] = CRITICAL
        approved.append(("Guaranteed", positive))
    for expected, positive in approved:
        admitted = lab.create(positive, dry_run=True)
        actual = admitted.get("status", {}).get("qosClass")
        lab.check("positive", f"Policy admits {positive['metadata']['name']} with {expected} QoS",
                  actual == expected, {"observed_qos": actual})
