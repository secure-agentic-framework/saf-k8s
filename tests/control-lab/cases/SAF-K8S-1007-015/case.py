"""Exercise a bounded synthetic node-onboarding decision and scheduler hold."""
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
CONTROL_ID = "SAF-K8S-1007-015"
NAMESPACE = "saf-test"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PAUSE_IMAGE = (
    "registry.k8s.io/pause:3.10.1@sha256:"
    "278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c"
)
HOLD_KEY = "saf-lab.example/onboarding-hold"
HOLD_VALUE = "pending-validation"
POD_NAME = "saf-1007-015-scheduling-probe"
CASE_LABEL = "saf-lab.example/control"
FIXTURE_LABEL = "saf-lab.example/fixture"
REQUIRED_SYNTHETIC_CHECKS = {
    "kubelet_hardening_attestation",
    "container_runtime_protection_attestation",
    "operating_system_baseline_attestation",
}
SCOPE = (
    "One disposable single-node Kind Kubernetes v1.36.1 cluster using the pinned Kind node image. "
    "The case observes allowlisted Node status.nodeInfo fields, applies one case-scoped NoSchedule "
    "taint to the default node, and creates one benign digest-pinned pause scheduling probe. A local "
    "decision function combines those observed Kind system fields with separately named, synthetic "
    "baseline evidence fixtures. This does not onboard a GPU node or validate a production pipeline, "
    "GPU/device readiness, a real kubelet/runtime/OS security configuration, immutable-root enforcement, "
    "or any production baseline attestation."
)


def node_metadata(lab):
    result = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)
    items = result.get("items", [])
    if len(items) != 1:
        lab.block("Expected exactly one default Kind node")
    node = items[0]
    info = node.get("status", {}).get("nodeInfo", {})
    observed = {
        "name": node.get("metadata", {}).get("name"),
        "uid": node.get("metadata", {}).get("uid"),
        "kubelet_version": info.get("kubeletVersion"),
        "container_runtime_version": info.get("containerRuntimeVersion"),
        "operating_system": info.get("operatingSystem"),
        "architecture": info.get("architecture"),
        "kernel_version": info.get("kernelVersion"),
    }
    if not all(observed.values()):
        lab.block("Allowlisted Node system metadata is incomplete")
    return observed


def system_fields_pass(observed):
    runtime = observed.get("container_runtime_version", "")
    return bool(
        observed.get("kubelet_version") == "v1.36.1"
        and runtime.startswith("containerd://")
        and observed.get("operating_system") == "linux"
        and observed.get("architecture") in {"amd64", "arm64"}
        and observed.get("kernel_version")
    )


def decide(observed, synthetic_evidence):
    """Return a decision; synthetic fixture attestations are not live configuration proof."""
    if not system_fields_pass(observed):
        return {"accepted": False, "reason": "observed_kind_system_fields_not_accepted"}
    if (synthetic_evidence.get("synthetic") is not True
            or synthetic_evidence.get("fixture_id") is None):
        return {"accepted": False, "reason": "synthetic_baseline_fixture_identity_invalid"}
    checks = synthetic_evidence.get("checks", {})
    if not isinstance(checks, dict) or set(checks) != REQUIRED_SYNTHETIC_CHECKS:
        return {"accepted": False, "reason": "synthetic_baseline_check_set_incomplete"}
    if any(checks.get(name) != "pass" for name in REQUIRED_SYNTHETIC_CHECKS):
        return {"accepted": False, "reason": "synthetic_baseline_attestation_failed"}
    return {"accepted": True, "reason": "observed_kind_fields_and_synthetic_baseline_fixture_pass"}


def create_probe(lab, node):
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": POD_NAME,
            "namespace": NAMESPACE,
            "labels": {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "true"},
        },
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "nodeSelector": {"kubernetes.io/hostname": node["name"]},
            "tolerations": [{
                "key": "node-role.kubernetes.io/control-plane",
                "operator": "Exists",
                "effect": "NoSchedule",
            }],
            "containers": [{
                "name": "pause-probe",
                "image": PAUSE_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "resources": {"requests": {"cpu": "1m", "memory": "4Mi"},
                              "limits": {"cpu": "10m", "memory": "16Mi"}},
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                    "runAsNonRoot": True,
                    "runAsUser": 65535,
                    "seccompProfile": {"type": "RuntimeDefault"},
                    "readOnlyRootFilesystem": True,
                },
            }],
        },
    }
    return lab.create(pod)


def observe_pending(lab, expected_uid):
    deadline = time.monotonic() + 35
    selected_event = None
    pod = None
    while time.monotonic() < deadline:
        pod = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pod", POD_NAME, "-o", "json").stdout)
        if pod.get("metadata", {}).get("uid") != expected_uid:
            lab.block("Observed probe UID does not match the created case-owned Pod")
        if (pod.get("status", {}).get("phase") != "Pending"
                or pod.get("spec", {}).get("nodeName")):
            lab.block("Probe did not remain Pending while the protective taint was present")
        events = json.loads(lab.kubectl(
            "-n", NAMESPACE, "get", "events", "-o", "json").stdout).get("items", [])
        for event in events:
            involved = event.get("involvedObject", {})
            if (involved.get("uid") == expected_uid and event.get("reason") == "FailedScheduling"
                    and "untolerated taint" in event.get("message", "").lower()):
                selected_event = {
                    "reason": event.get("reason"),
                    "message": event.get("message"),
                    "involved_object_uid": involved.get("uid"),
                }
                break
        if selected_event:
            break
        time.sleep(0.5)
    if not selected_event:
        lab.block("Scheduler did not expose a FailedScheduling event for the case-owned hold taint")
    return pod, selected_event


def wait_running(lab, expected_uid):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        pod = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pod", POD_NAME, "-o", "json").stdout)
        if pod.get("metadata", {}).get("uid") != expected_uid:
            lab.block("Probe UID changed during acceptance check")
        if pod.get("status", {}).get("phase") == "Running":
            container = pod.get("status", {}).get("containerStatuses", [{}])[0]
            if container.get("ready") and container.get("imageID"):
                return pod, {"ready": container["ready"], "image_id": container["imageID"]}
        if pod.get("status", {}).get("phase") in {"Failed", "Succeeded"}:
            lab.block("Digest-pinned pause probe did not reach Running")
        time.sleep(1)
    lab.block("Accepted scheduling probe did not become Ready")


def run(lab):
    observed = node_metadata(lab)
    node_name = observed["name"]
    taint = f"{HOLD_KEY}={HOLD_VALUE}:NoSchedule"
    lab.kubectl("taint", "nodes", node_name, taint)
    held_node = json.loads(lab.kubectl("get", "node", node_name, "-o", "json").stdout)
    taints = held_node.get("spec", {}).get("taints", [])
    held = any(item.get("key") == HOLD_KEY and item.get("value") == HOLD_VALUE
               and item.get("effect") == "NoSchedule" for item in taints)
    if not held:
        lab.block("Case-scoped protective NoSchedule taint was not observable on the default node")

    created_probe = create_probe(lab, observed)
    pending_pod, scheduling_event = observe_pending(lab, created_probe["metadata"]["uid"])
    lab.check(
        "positive",
        "The protective hold taint independently leaves the benign scheduler probe Pending",
        pending_pod.get("status", {}).get("phase") == "Pending"
        and not pending_pod.get("spec", {}).get("nodeName")
        and "untolerated taint" in scheduling_event.get("message", "").lower(),
        {"hold_taint_observed": held, "pod_phase": "Pending", "pod_node_name_empty": True,
         "scheduler_reported_hold_taint": True, "event_bound_to_probe_uid": True},
    )

    node_after_hold = json.loads(lab.kubectl("get", "node", node_name, "-o", "json").stdout)
    remains_held = any(item.get("key") == HOLD_KEY and item.get("value") == HOLD_VALUE
                       and item.get("effect") == "NoSchedule"
                       for item in node_after_hold.get("spec", {}).get("taints", []))
    rejected_evidence = json.loads((FIXTURES / "synthetic-baseline-rejected.json").read_text())
    rejected = decide(observed, rejected_evidence)
    lab.check(
        "red",
        "Incomplete synthetic baseline evidence is rejected while the node remains held",
        not rejected["accepted"] and rejected["reason"] == "synthetic_baseline_check_set_incomplete"
        and remains_held,
        {"decision": rejected, "synthetic_fixture_id": rejected_evidence["fixture_id"],
         "synthetic_checks": rejected_evidence["checks"], "hold_taint_present": remains_held,
         "observed_system_fields_pass": system_fields_pass(observed)},
    )

    accepted_evidence = json.loads((FIXTURES / "synthetic-baseline-accepted.json").read_text())
    accepted = decide(observed, accepted_evidence)
    lab.check(
        "green",
        "Complete synthetic baseline evidence and observed Kind system fields produce acceptance",
        accepted["accepted"] is True and system_fields_pass(observed),
        {"decision": accepted, "synthetic_fixture_id": accepted_evidence["fixture_id"],
         "synthetic_checks": accepted_evidence["checks"],
         "observed_system_fields": {"kubelet_version": observed["kubelet_version"],
                                    "runtime_is_containerd": observed["container_runtime_version"].startswith("containerd://"),
                                    "operating_system": observed["operating_system"],
                                    "supported_architecture": observed["architecture"] in {"amd64", "arm64"},
                                    "kernel_version_present": bool(observed["kernel_version"])},
         "synthetic_evidence_is_live_measurement": False},
    )

    lab.kubectl("taint", "nodes", node_name, f"{HOLD_KEY}-")
    updated_node = json.loads(lab.kubectl("get", "node", node_name, "-o", "json").stdout)
    same_node_uid = updated_node.get("metadata", {}).get("uid") == observed["uid"]
    remaining_hold = [item for item in updated_node.get("spec", {}).get("taints", [])
                      if item.get("key") == HOLD_KEY]
    running_pod, container_status = wait_running(lab, created_probe["metadata"]["uid"])
    lab.check(
        "positive",
        "After synthetic acceptance removes only the case hold, the same probe schedules and runs",
        accepted["accepted"] and not remaining_hold and same_node_uid
        and running_pod.get("spec", {}).get("nodeName") == node_name
        and container_status["ready"],
        {"decision": accepted["reason"], "case_hold_removed": not remaining_hold,
         "same_probe_uid": running_pod["metadata"]["uid"] == created_probe["metadata"]["uid"],
         "scheduled_to_same_node_uid": same_node_uid and running_pod["spec"]["nodeName"] == node_name,
         "container_ready": container_status["ready"], "runtime_image_id_present": bool(container_status["image_id"])},
    )

    evidence = {
        "control_id": CONTROL_ID,
        "scope": SCOPE,
        "cluster_node": observed,
        "protective_hold": {"key": HOLD_KEY, "value": HOLD_VALUE, "effect": "NoSchedule",
                            "pending_scheduler_event": scheduling_event,
                            "removed_after_synthetic_acceptance": not remaining_hold},
        "decisions": {
            "rejected": {"fixture": rejected_evidence, "result": rejected},
            "accepted": {"fixture": accepted_evidence, "result": accepted},
        },
        "probe": {"uid": running_pod["metadata"]["uid"],
                  "scheduled_node": running_pod.get("spec", {}).get("nodeName"),
                  "phase": running_pod.get("status", {}).get("phase"),
                  "container": container_status},
        "checks": lab.checks,
        "secrets_included": False,
        "external_targets_contacted": False,
        "production_baseline_observed": False,
        "gpu_hardware_or_readiness_observed": False,
    }
    (lab.evidence / "node-onboarding.raw.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
