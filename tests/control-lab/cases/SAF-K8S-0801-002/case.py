"""Verify scheduler accounting for declared synthetic accelerator profile keys."""

import json
import time

SCOPE = "Live Kubernetes scheduler behavior for inert modeled MIG extended resources, with no NVIDIA runtime."
EXPECTED = "fixture.example/mig-profile-a"
WRONG = "fixture.example/mig-profile-b"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"


def add_workload(lab, name, key, units="1"):
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
                "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [{"name": "fixture", "image": IMAGE,
                                         "command": ["python", "-c", "import time; time.sleep(220)"],
                                         "securityContext": {"allowPrivilegeEscalation": False,
                                                             "readOnlyRootFilesystem": True,
                                                             "capabilities": {"drop": ["ALL"]}},
                                         "resources": {"requests": {key: units, "cpu": "5m", "memory": "12Mi"},
                                                       "limits": {key: units, "cpu": "100m", "memory": "40Mi"}}}]}})


def record(lab, name):
    return json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)


def rejected_by_scheduler(lab, name, resource):
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        result = record(lab, name)
        if result["spec"].get("nodeName"):
            return False
        for condition in result.get("status", {}).get("conditions", []):
            if (condition.get("type") == "PodScheduled" and condition.get("reason") == "Unschedulable"
                    and f"Insufficient {resource}" in condition.get("message", "")):
                return True
        time.sleep(0.5)
    lab.block("The scheduler did not give the expected resource-specific decision")


def advertise(lab, node):
    field = EXPECTED.replace("/", "~1")
    lab.kubectl("patch", "node", node, "--subresource=status", "--type=json", "-p",
                json.dumps([{"op": "add", "path": f"/status/capacity/{field}", "value": "2"}]))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = json.loads(lab.kubectl("get", "node", node, "-o", "json").stdout)["status"]
        if status.get("allocatable", {}).get(EXPECTED) == "2":
            return status["allocatable"]
        time.sleep(0.5)
    lab.block("The owned node did not report the synthetic allocatable resource")


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    node, = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    node_name = node["metadata"]["name"]
    name = "matches-profile"
    add_workload(lab, name, EXPECTED, units="2")
    missing = rejected_by_scheduler(lab, name, EXPECTED)
    lab.check("red", "The scheduler rejects the exact modeled profile while the node does not advertise it",
              missing, {"matching_request_unschedulable_before_advertisement": missing})

    published = advertise(lab, node_name)
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=80s", timeout=90)
    matched = record(lab, name)["spec"]["nodeName"] == node_name
    lab.check("green", "The same Pod is scheduled once both units of its requested profile become allocatable",
              matched and published[EXPECTED] == "2" and WRONG not in published,
              {"matching_profile_scheduled": matched, "matching_profile_allocatable": 2, "other_profile_advertised": False})

    add_workload(lab, "wrong-profile", WRONG)
    add_workload(lab, "over-capacity", EXPECTED)
    profile_missing = rejected_by_scheduler(lab, "wrong-profile", WRONG)
    capacity_used = rejected_by_scheduler(lab, "over-capacity", EXPECTED)
    lab.check("positive", "Kubernetes does not substitute an unknown profile or overcommit the two modeled units",
              profile_missing and capacity_used, {"unknown_profile_unschedulable": profile_missing,
                                                 "capacity_exhaustion_unschedulable": capacity_used})
    (lab.evidence / "mig-scheduler-observations.json").write_text(json.dumps(
        {"fixture_resource": EXPECTED, "allocatable": 2, "matching_pod_scheduled": matched,
         "unknown_profile_unschedulable": profile_missing, "capacity_exhaustion_unschedulable": capacity_used,
         "hardware_or_vendor_plugin_tested": False}, indent=2) + "\n")
