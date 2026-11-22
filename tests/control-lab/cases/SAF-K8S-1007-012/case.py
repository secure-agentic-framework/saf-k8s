"""Exercise a synthetic AI component compatibility gate against observed cluster inventory."""
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
MATRIX_PATH = HERE / "fixtures" / "compatibility-matrix.json"
CONTROL_ID = "SAF-K8S-1007-012"
NAMESPACE = "saf-test"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
MOCK_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
CASE_LABEL = "saf-lab.example/control"
FIXTURE_LABEL = "saf-lab.example/fixture"
COMPONENT_ANNOTATION = "saf-lab.example/component-version"
COMPONENTS = (
    "gpu-driver", "cuda-toolkit", "ai-operator", "device-plugin", "serving-framework",
)
SCOPE = (
    "One disposable single-node Kind Kubernetes v1.36.1 cluster; actual Kubernetes API discovery; "
    "five case-owned zero-replica mock Deployments and a local compatibility decision over synthetic component metadata. "
    "A blocked candidate is not applied and a permitted candidate changes only a Deployment "
    "metadata annotation. No GPU, CUDA runtime, operator, device plugin, model server, model "
    "artifact, training/inference behavior, or vendor compatibility is installed or tested. "
    "No external feed, target, secret, or non-case workload is accessed."
)


def _deployment_name(component):
    return "saf-1007-012-" + component


def _deployment(component, version):
    name = _deployment_name(component)
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "true"},
            "annotations": {
                "saf-lab.example/component": component,
                COMPONENT_ANNOTATION: version,
                "saf-lab.example/metadata-class": "synthetic-only",
            },
        },
        "spec": {
            "replicas": 0,
            "selector": {"matchLabels": {"saf-lab.example/workload": name}},
            "template": {
                "metadata": {"labels": {"saf-lab.example/workload": name}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 65534,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [{
                        "name": "mock-component",
                        "image": MOCK_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "-c", "import time; time.sleep(3600)"],
                        "securityContext": {
                            "readOnlyRootFilesystem": True,
                            "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "resources": {
                            "requests": {"cpu": "5m", "memory": "16Mi"},
                            "limits": {"cpu": "50m", "memory": "48Mi"},
                        },
                    }],
                },
            },
        },
    }


def _inventory(lab):
    # Discovery responses are public API metadata, not object payloads.
    core = json.loads(lab.kubectl("get", "--raw", "/api").stdout)
    grouped = json.loads(lab.kubectl("get", "--raw", "/apis").stdout)
    versions = set(core.get("versions", []))
    for group in grouped.get("groups", []):
        versions.update(
            item.get("groupVersion") for item in group.get("versions", [])
            if item.get("groupVersion")
        )
    deployment_response = json.loads(lab.kubectl("get", "deployments", "-o", "json").stdout)
    deployments = {}
    for item in deployment_response.get("items", []):
        metadata = item.get("metadata", {})
        labels = metadata.get("labels", {})
        if labels.get(CASE_LABEL) != CONTROL_ID or labels.get(FIXTURE_LABEL) != "true":
            continue
        annotations = metadata.get("annotations", {})
        component = annotations.get("saf-lab.example/component")
        containers = item.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        if not component or component in deployments or len(containers) != 1:
            lab.block("Owned Deployment inventory has an incomplete component record")
        deployments[component] = {
            "name": metadata.get("name"),
            "uid": metadata.get("uid"),
            "api_version": item.get("apiVersion"),
            "version": annotations.get(COMPONENT_ANNOTATION),
            "metadata_class": annotations.get("saf-lab.example/metadata-class"),
            "replicas": item.get("spec", {}).get("replicas"),
            "ready_replicas": item.get("status", {}).get("readyReplicas", 0),
            "image": containers[0].get("image"),
        }
    return {
        "served_api_versions": sorted(version for version in versions if version),
        "deployment_components": deployments,
        "raw_api_discovery": {"core": core, "groups": grouped},
        "raw_owned_deployments": [
            item for item in deployment_response.get("items", [])
            if item.get("metadata", {}).get("labels", {}).get(CASE_LABEL) == CONTROL_ID
            and item.get("metadata", {}).get("labels", {}).get(FIXTURE_LABEL) == "true"
        ],
    }


def _decide(matrix, inventory, change):
    observed_versions = inventory["deployment_components"]
    reasons = []
    if not set(matrix["required_api_versions"]).issubset(inventory["served_api_versions"]):
        reasons.append("required_api_version_not_served")
    component = change["target_component"]
    target = observed_versions.get(component)
    if target is None:
        reasons.append("target_component_missing_from_observed_deployments")
    elif target.get("version") != change["expected_current"]:
        reasons.append("target_current_version_differs_from_matrix")
    if set(observed_versions) != set(matrix["inventory"]):
        reasons.append("observed_component_set_differs_from_matrix")
    for name, expected in matrix["inventory"].items():
        observed = observed_versions.get(name)
        if observed is None or observed.get("version") != expected:
            reasons.append("observed_baseline_differs:" + name)
    for name, expected in change["requires"].items():
        observed = observed_versions.get(name)
        if observed is None or observed.get("version") != expected:
            reasons.append("dependency_mismatch:" + name)
    return {
        "decision": "permit" if not reasons else "block",
        "change_id": change["change_id"],
        "target_component": component,
        "current_version": target.get("version") if target else None,
        "target_version": change["target_version"],
        "reasons": reasons,
    }


def apply_candidate(lab, matrix, inventory, change):
    decision = _decide(matrix, inventory, change)
    if decision["decision"] == "permit":
        patch = {"metadata": {"annotations": {COMPONENT_ANNOTATION: change["target_version"]}}}
        lab.kubectl("patch", "deployment", _deployment_name(change["target_component"]),
                    "--type=merge", "-p", json.dumps(patch))
    return decision


def run(lab):
    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    if (matrix.get("fixture_id") != "SYNTH-SAF-K8S-1007-012-MATRIX-001"
            or matrix.get("classification") != "synthetic-only"
            or matrix.get("real_compatibility_claims") is not False
            or set(matrix.get("inventory", {})) != set(COMPONENTS)):
        lab.block("Compatibility matrix identity or synthetic-only shape is invalid")

    server = json.loads(lab.kubectl("version", "-o", "json").stdout).get("serverVersion", {})
    observed_server_version = server.get("gitVersion")
    if observed_server_version != "v1.36.1":
        lab.block("The observed API server is not Kubernetes v1.36.1")

    for component in COMPONENTS:
        lab.create(_deployment(component, matrix["inventory"][component]))
    lab.kubectl("wait", "--for=jsonpath={.status.observedGeneration}=1",
                *(f"deployment/{_deployment_name(name)}" for name in COMPONENTS),
                "--timeout=20s")
    before = _inventory(lab)
    expected_apis = set(matrix["required_api_versions"])
    expected_components = set(COMPONENTS)
    inventory_complete = (
        expected_apis.issubset(before["served_api_versions"])
        and set(before["deployment_components"]) == expected_components
        and all(
            item["name"] == _deployment_name(component)
            and item["api_version"] == "apps/v1"
            and item["version"] == matrix["inventory"][component]
            and item["metadata_class"] == "synthetic-only"
            and item["uid"]
            and item["replicas"] == 0
            and item["ready_replicas"] == 0
            and item["image"] == MOCK_IMAGE
            for component, item in before["deployment_components"].items()
        )
    )
    lab.check(
        "positive",
        "Observed API discovery and all five zero-replica Deployments match the local synthetic baseline",
        inventory_complete,
        {"server_version": observed_server_version, "owned_components": sorted(before["deployment_components"]),
         "component_count": len(before["deployment_components"])},
    )

    changes = {item["expected_decision"]: item for item in matrix["decisions"]}
    blocked_change = changes.get("block")
    permitted_change = changes.get("permit")
    if not blocked_change or not permitted_change:
        lab.block("Fixture must include one expected block and one expected permit decision")
    blocked = apply_candidate(lab, matrix, before, blocked_change)
    after_block = _inventory(lab)
    unchanged_after_block = (
        after_block["deployment_components"] == before["deployment_components"]
        and {o["metadata"]["name"]: o["metadata"]["resourceVersion"] for o in after_block["raw_owned_deployments"]}
        == {o["metadata"]["name"]: o["metadata"]["resourceVersion"] for o in before["raw_owned_deployments"]}
    )
    lab.check(
        "red",
        "A candidate with dependency versions absent from observed inventory is blocked before mutation",
        blocked["decision"] == "block" and "dependency_mismatch:gpu-driver" in blocked["reasons"]
        and unchanged_after_block,
        {"decision": blocked, "deployment_records_unchanged": unchanged_after_block},
    )

    permitted = apply_candidate(lab, matrix, after_block, permitted_change)
    if permitted["decision"] != "permit":
        lab.block("The fixture's compatible metadata-only change was not permitted")
    after = _inventory(lab)
    target_after = after["deployment_components"].get(permitted_change["target_component"], {})
    target_name = _deployment_name(permitted_change["target_component"])
    raw_before = {item.get("metadata", {}).get("name"): item
                  for item in before["raw_owned_deployments"]}.get(target_name, {})
    raw_after = {item.get("metadata", {}).get("name"): item
                 for item in after["raw_owned_deployments"]}.get(target_name, {})
    annotations_before = raw_before.get("metadata", {}).get("annotations", {})
    annotations_after = raw_after.get("metadata", {}).get("annotations", {})
    other_annotations_unchanged = (
        {key: value for key, value in annotations_before.items() if key != COMPONENT_ANNOTATION}
        == {key: value for key, value in annotations_after.items() if key != COMPONENT_ANNOTATION}
    )
    other_versions_unchanged = all(
        after["deployment_components"].get(name, {}).get("version") == version
        for name, version in matrix["inventory"].items()
        if name != permitted_change["target_component"]
    )
    update_applied = (
        target_after.get("version") == permitted_change["target_version"]
        and target_after.get("uid") == before["deployment_components"][permitted_change["target_component"]]["uid"]
        and raw_before.get("spec") == raw_after.get("spec")
        and other_annotations_unchanged
        and other_versions_unchanged
        and after["served_api_versions"] == before["served_api_versions"]
    )
    lab.check(
        "green",
        "A matrix-permitted candidate updates only its observed synthetic Deployment annotation",
        update_applied,
        {"decision": permitted, "target_annotation_read_back": target_after.get("version"),
         "only_metadata_changed": update_applied,
         "deployment_spec_unchanged": raw_before.get("spec") == raw_after.get("spec"),
         "other_annotations_unchanged": other_annotations_unchanged},
    )

    evidence = {
        "control_id": CONTROL_ID,
        "scope": SCOPE,
        "fixture_id": matrix["fixture_id"],
        "classification": "synthetic-only",
        "observed_server_version": observed_server_version,
        "served_api_versions": before["served_api_versions"],
        "inventory_before": before["deployment_components"],
        "raw_api_discovery": before["raw_api_discovery"],
        "raw_owned_deployments_before": before["raw_owned_deployments"],
        "block_decision": blocked,
        "raw_owned_deployments_after_block": after_block["raw_owned_deployments"],
        "permit_decision": permitted,
        "inventory_after": after["deployment_components"],
        "raw_owned_deployments_after": after["raw_owned_deployments"],
        "secrets_included": False,
        "external_targets_contacted": False,
        "gpu_or_cuda_runtime_tested": False,
        "real_compatibility_claims": False,
        "checks": lab.checks,
    }
    (lab.evidence / "compatibility-governance.raw.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
