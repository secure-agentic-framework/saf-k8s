"""Exercise scoped node-taint scheduling and parse fictional onboarding evidence."""
import json
import re
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
FIXTURE_PATH = HERE / "fixtures" / "evidence.json"
LABEL = "saf-k8s.example/control-1007-016-candidate"
TAINT = "saf-k8s.example/gpu-candidate"
WORKLOAD_LABEL = "saf-k8s.example/control-1007-016-workload"
PAUSE_IMAGE = (
    "registry.k8s.io/pause:3.10.1@sha256:"
    "278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c"
)
SCOPE = (
    "One disposable default-layout Kind v1.36.1 node. The case labels that node as a synthetic candidate, "
    "observes an inert digest-pinned pause Pod schedule before a fixture-scoped NoSchedule taint, then "
    "observes an untolerating Pod remain unscheduled and a tolerating Pod receive a scheduler-assigned "
    "nodeName. It parses local fictional attestation and driver-evidence JSON fixtures and records mock "
    "eligibility decisions. This does not provision or identify GPU hardware, install or inspect a driver, "
    "cryptographically verify attestation, verify signatures or real checksums, integrate an onboarding "
    "gate with Kubernetes, or establish production label/taint authority."
)


def read_fixture():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def assess_evidence(attestation, driver, node_alias):
    """Parse fixture fields only; no cryptographic or host verification is performed."""
    attestation_ok = (
        attestation.get("schema") == "urn:example:saf-k8s:attestation-fixture:v1"
        and attestation.get("source_kind") == "synthetic-fixture"
        and attestation.get("subject") == node_alias
        and attestation.get("fixture_result") == "pass"
        and attestation.get("verification_performed") is False
    )
    digest_shape_ok = all(
        isinstance(driver.get(field), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", driver[field]) is not None
        for field in ("observed_digest", "approved_digest")
    )
    driver_ok = (
        driver.get("schema") == "urn:example:saf-k8s:driver-fixture:v1"
        and driver.get("source_kind") == "synthetic-fixture"
        and driver.get("subject") == node_alias
        and driver.get("component") == "mock-gpu-driver"
        and driver.get("fixture_result") == "pass"
        and digest_shape_ok
        and driver.get("observed_digest") == driver.get("approved_digest")
    )
    return {
        "decision": "eligible" if attestation_ok and driver_ok else "hold",
        "evidence_class": "synthetic-fixture-only",
        "attestation_fields_match_fixture_contract": attestation_ok,
        "driver_fields_match_fixture_contract": driver_ok,
        "cryptographic_attestation_verified": False,
        "host_driver_or_checksum_inspected": False,
    }


def pod(name, *, tolerates_candidate_taint, existing_tolerations):
    spec = {
        "automountServiceAccountToken": False,
        "restartPolicy": "Never",
        "nodeSelector": {LABEL: "true"},
        "containers": [{"name": "inert", "image": PAUSE_IMAGE,
                        "imagePullPolicy": "IfNotPresent"}],
    }
    spec["tolerations"] = list(existing_tolerations)
    # Tolerate only the exact taints already present before this case adds its own,
    # so scheduler outcomes isolate the fixture-scoped taint.
    if tolerates_candidate_taint:
        spec["tolerations"].append({
            "key": TAINT, "operator": "Equal", "value": "reserved", "effect": "NoSchedule",
        })
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "labels": {WORKLOAD_LABEL: "synthetic"}},
        "spec": spec,
    }


def as_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def save_raw(lab, name, value):
    (lab.evidence / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                                     encoding="utf-8")


def pod_record(lab, name):
    return as_json(lab, "get", "pod", name)


def wait_for(lab, name, predicate, seconds=30):
    end = time.monotonic() + seconds
    record = pod_record(lab, name)
    while time.monotonic() < end:
        if predicate(record):
            return record
        time.sleep(0.5)
        record = pod_record(lab, name)
    return record


def scheduled(record):
    return bool(record.get("spec", {}).get("nodeName"))


def unschedulable_for_fixture_taint(record):
    status = record.get("status", {})
    condition = next((item for item in status.get("conditions", [])
                      if item.get("type") == "PodScheduled"), {})
    message = condition.get("message", "").lower()
    return (not scheduled(record) and condition.get("status") == "False"
            and condition.get("reason") == "Unschedulable"
            and "untolerated taint" in message)


def safe_node_observation(node):
    metadata = node.get("metadata", {})
    status = node.get("status", {})
    return {
        "name": metadata.get("name"),
        "uid": metadata.get("uid"),
        "candidate_label": metadata.get("labels", {}).get(LABEL),
        "taints": [taint for taint in node.get("spec", {}).get("taints", [])
                   if taint.get("key") == TAINT],
        "ready": any(condition.get("type") == "Ready" and condition.get("status") == "True"
                     for condition in status.get("conditions", [])),
    }


def safe_pod_observation(record):
    spec = record.get("spec", {})
    status = record.get("status", {})
    condition = next((item for item in status.get("conditions", [])
                      if item.get("type") == "PodScheduled"), {})
    return {
        "name": record.get("metadata", {}).get("name"),
        "node_name": spec.get("nodeName"),
        "phase": status.get("phase"),
        "scheduled_condition": {key: condition.get(key) for key in ("status", "reason", "message")
                                if key in condition},
        "image": spec.get("containers", [{}])[0].get("image"),
        "tolerations": spec.get("tolerations", []),
    }


def run(lab):
    fixture = read_fixture()
    nodes = as_json(lab, "get", "nodes").get("items", [])
    if len(nodes) != 1:
        lab.block(f"Expected exactly one node in the default Kind profile; observed {len(nodes)}")
    node = nodes[0]
    node_name = node.get("metadata", {}).get("name")
    if not node_name:
        lab.block("Kind node has no API-observed name")
    existing_tolerations = []
    for taint in node.get("spec", {}).get("taints", []):
        if taint.get("key") == TAINT or taint.get("effect") not in ("NoSchedule", "NoExecute"):
            continue
        item = {"key": taint["key"], "operator": "Exists", "effect": taint["effect"]}
        if taint.get("value"):
            item.update(operator="Equal", value=taint["value"])
        existing_tolerations.append(item)
    lab.kubectl("label", "node", node_name, f"{LABEL}=true", "--overwrite")
    before_name = "saf-1007-016-before-taint"
    lab.create(pod(before_name, tolerates_candidate_taint=False,
                   existing_tolerations=existing_tolerations))
    before = wait_for(lab, before_name, scheduled)
    before_node = before.get("spec", {}).get("nodeName")
    lab.check("red", "Before the candidate taint, an inert Pod can schedule to the candidate node",
              before_node == node_name,
              {"scheduler_assigned_candidate_node": before_node == node_name,
               "fixture_taint_present": False})

    lab.kubectl("taint", "node", node_name, f"{TAINT}=reserved:NoSchedule")
    held_node = as_json(lab, "get", "node", node_name)
    case_taints = safe_node_observation(held_node)["taints"]
    held = case_taints == [{"key": TAINT, "value": "reserved", "effect": "NoSchedule"}]
    if not held:
        lab.block("The case-owned NoSchedule taint did not persist")
    denied_name = "saf-1007-016-no-toleration"
    lab.create(pod(denied_name, tolerates_candidate_taint=False,
                   existing_tolerations=existing_tolerations))
    denied = wait_for(lab, denied_name, unschedulable_for_fixture_taint)
    taint_denial = unschedulable_for_fixture_taint(denied)
    lab.check("green", "The scheduler leaves an untolerating candidate Pod unscheduled for the scoped taint",
              taint_denial and held,
              {"scheduler_reported_untolerated_taint": taint_denial,
               "scoped_taint_read_back": held, "node_name_empty": not scheduled(denied)})

    rejected_attestation = assess_evidence(fixture["negative_attestation"],
                                           fixture["driver_evidence"], fixture["node_alias"])
    rejected_driver = assess_evidence(fixture["attestation"],
                                      fixture["negative_driver_evidence"], fixture["node_alias"])
    allowed = assess_evidence(fixture["attestation"], fixture["driver_evidence"],
                              fixture["node_alias"])
    save_raw(lab, "synthetic-evidence-assessment.raw.json", {
        "fixture_notice": fixture["fixture_notice"],
        "node_alias": fixture["node_alias"],
        "negative_attestation_assessment": rejected_attestation,
        "negative_driver_assessment": rejected_driver,
        "positive_fixture_assessment": allowed,
    })
    negative_evidence_held = (
        rejected_attestation["decision"] == "hold"
        and not rejected_attestation["attestation_fields_match_fixture_contract"]
        and rejected_attestation["driver_fields_match_fixture_contract"]
        and rejected_driver["decision"] == "hold"
        and rejected_driver["attestation_fields_match_fixture_contract"]
        and not rejected_driver["driver_fields_match_fixture_contract"]
    )
    lab.check("green", "Synthetic attestation failure and driver digest mismatch each independently yield hold",
              negative_evidence_held,
              {"attestation_failure": rejected_attestation,
               "driver_digest_mismatch": rejected_driver})

    allowed_name = "saf-1007-016-mock-approved"
    if allowed["decision"] == "eligible":
        lab.create(pod(allowed_name, tolerates_candidate_taint=True,
                       existing_tolerations=existing_tolerations))
        approved = wait_for(lab, allowed_name, scheduled)
        approved_node = approved.get("spec", {}).get("nodeName")
    else:
        approved = {}
        approved_node = None
    lab.check("positive", "Matching synthetic fixture records permit an inert Pod that tolerates the taint to schedule",
              allowed["decision"] == "eligible" and approved_node == node_name,
              {"mock_decision": allowed["decision"], "scheduler_assigned_candidate_node": approved_node == node_name,
               "cryptographic_attestation_verified": False,
               "host_driver_or_checksum_inspected": False})

    current_node = as_json(lab, "get", "node", node_name)
    save_raw(lab, "scheduling-observations.raw.json", {
        "node": safe_node_observation(current_node),
        "before_taint": safe_pod_observation(before),
        "without_toleration": safe_pod_observation(denied),
        "mock_eligible_with_toleration": safe_pod_observation(approved) if approved else None,
        "scope_notice": "Only API-visible scheduling and fixture-scoped taint fields are recorded.",
    })
