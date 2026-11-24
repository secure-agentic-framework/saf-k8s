"""Exercise a synthetic AI component compatibility gate against observed cluster inventory."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import time


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
    "metadata annotation with an observed resourceVersion precondition. Explicit synthetic "
    "approval data binds native admission to the full proposed tuple, change sequence, named "
    "checks, matrix digest, change ID, image and release. The candidate is rejected when "
    "approval is missing, stale or mismatched; matching approval admits the "
    "synthetic workload with its verified release marker. Hardware and actual "
    "GPU software compatibility require their own evidence."
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
        name = _deployment_name(change["target_component"])
        current = next(item for item in inventory["raw_owned_deployments"]
                       if item["metadata"]["name"] == name)
        resource_version = current["metadata"]["resourceVersion"]
        patch = [
            {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
            {"op": "add", "path": "/metadata/annotations/" + COMPONENT_ANNOTATION.replace("/", "~1"),
             "value": change["target_version"]},
        ]
        lab.kubectl("patch", "deployment", name, "--type=json", "-p", json.dumps(patch))
    return decision


def _live_gate(lab, matrix, approved, stale_precondition_ok):
    name = "synthetic-matrix-rollout"
    target = "approved-workload"
    target_resource = _deployment_name(target)
    digest = sha256(json.dumps(matrix, sort_keys=True).encode()).hexdigest()
    release = approved["target_version"]
    tuple_data = dict(matrix["inventory"])
    tuple_data[approved["target_component"]] = release
    sequence = [
        "verify:gpu-driver=" + matrix["inventory"]["gpu-driver"],
        "verify:cuda-toolkit=" + matrix["inventory"]["cuda-toolkit"],
        "verify:ai-operator=" + matrix["inventory"]["ai-operator"],
        "verify:device-plugin=" + matrix["inventory"]["device-plugin"],
        "update:serving-framework:" + approved["current_version"] + "->" + release,
    ]
    checks = [
        {"name": "functional.synthetic-marker-and-ready", "result": "synthetic-pass"},
        {"name": "security.native-admission-denies-mismatch", "result": "synthetic-pass"},
        {"name": "reliability.stale-resource-version-no-mutation", "result": "synthetic-pass"},
    ]
    tuple_digest = sha256(json.dumps(tuple_data, sort_keys=True).encode()).hexdigest()
    sequence_digest = sha256(json.dumps(sequence, separators=(",", ":")).encode()).hexdigest()
    checks_digest = sha256(json.dumps(checks, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    approval = {
        "matrix-sha256": digest,
        "tuple-sha256": tuple_digest,
        "change-id": approved["change_id"],
        "sequence-sha256": sequence_digest,
        "checks-sha256": checks_digest,
        "release": release,
        "image": MOCK_IMAGE,
        "tuple": json.dumps(tuple_data, sort_keys=True, separators=(",", ":")),
        "sequence": json.dumps(sequence, separators=(",", ":")),
        "checks": json.dumps(checks, sort_keys=True, separators=(",", ":")),
    }
    annotations = {
        "saf-lab.example/matrix-sha256": digest,
        "saf-lab.example/tuple-sha256": tuple_digest,
        "saf-lab.example/change-id": approved["change_id"],
        "saf-lab.example/sequence-sha256": sequence_digest,
        "saf-lab.example/checks-sha256": checks_digest,
    }
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf-lab.example/admission-scope=" + CONTROL_ID, "--overwrite")
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
        "metadata": {"name": name},
        "data": approval,
    })
    lab.create({
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": name},
        "spec": {
            "failurePolicy": "Fail",
            "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
            "matchConstraints": {"resourceRules": [
                {"apiGroups": ["apps"], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"],
                 "resources": ["deployments"]},
            ]},
            "matchConditions": [{"name": "owned-target", "expression":
                "request.namespace == '" + NAMESPACE + "' && object.metadata.name == '" + target_resource + "'"}],
            "validations": [{
                "expression": (
                    "params != null && object.metadata.namespace == '" + NAMESPACE + "' && "
                    "object.metadata.name == '" + target_resource + "' && "
                    "has(object.metadata.labels) && object.metadata.labels['" + CASE_LABEL + "'] == '" + CONTROL_ID + "' && "
                    "has(object.metadata.annotations) && "
                    "object.metadata.annotations['saf-lab.example/matrix-sha256'] == params.data['matrix-sha256'] && "
                    "object.metadata.annotations['saf-lab.example/tuple-sha256'] == params.data['tuple-sha256'] && "
                    "object.metadata.annotations['saf-lab.example/change-id'] == params.data['change-id'] && "
                    "object.metadata.annotations['saf-lab.example/sequence-sha256'] == params.data['sequence-sha256'] && "
                    "object.metadata.annotations['saf-lab.example/checks-sha256'] == params.data['checks-sha256'] && "
                    "object.spec.template.spec.containers.size() == 1 && "
                    "object.spec.template.spec.containers[0].image == params.data['image'] && "
                    "object.spec.template.spec.containers[0].env.exists(e, "
                    "e.name == 'SAF_RELEASE' && has(e.value) && e.value == params.data['release'])"
                ),
                "message": "The synthetic rollout requires exact compatibility approval",
            }],
        },
    })
    lab.create({
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": name},
        "spec": {
            "policyName": name, "validationActions": ["Deny"],
            "paramRef": {"name": name, "namespace": NAMESPACE, "parameterNotFoundAction": "Deny"},
            "matchResources": {
                "namespaceSelector": {"matchLabels": {"saf-lab.example/admission-scope": CONTROL_ID}},
            },
        },
    })
    candidate = _deployment(target, release)
    candidate["metadata"]["annotations"].update(annotations)
    candidate["spec"]["replicas"] = 1
    fixture = candidate["spec"]["template"]["spec"]["containers"][0]
    fixture["env"] = [{"name": "SAF_RELEASE", "value": release}]
    fixture["command"] = ["python", "-B", "-u", "-c",
                         "import os,time; print(os.environ['SAF_RELEASE']); time.sleep(180)"]
    def wait_for_admission(expected_denial=None):
        for _ in range(25):
            probe = lab.create(candidate, dry_run=True, allow_failure=True)
            if expected_denial is None and probe.returncode == 0:
                return
            if expected_denial and probe.returncode != 0 and expected_denial in probe.stderr:
                return
            time.sleep(1)
        lab.block("The synthetic approval binding did not settle")

    wait_for_admission()

    def denied_case(description, attempted, missing_parameter=False, apply=False):
        if missing_parameter:
            lab.kubectl("patch", "validatingadmissionpolicybinding", name, "--type=merge", "-p",
                        json.dumps({"spec": {"paramRef": {"name": "missing-synthetic-approval",
                                                            "namespace": NAMESPACE,
                                                            "parameterNotFoundAction": "Deny"}}}))
            wait_for_admission("no params found for policy binding")
        result = lab.create(attempted, dry_run=not apply, allow_failure=True)
        if missing_parameter:
            lab.kubectl("patch", "validatingadmissionpolicybinding", name, "--type=merge", "-p",
                        json.dumps({"spec": {"paramRef": {"name": name, "namespace": NAMESPACE,
                                                            "parameterNotFoundAction": "Deny"}}}))
            wait_for_admission()
        absent = not lab.kubectl("get", "deployment", target_resource, "--ignore-not-found", "-o", "name").stdout.strip()
        if missing_parameter:
            denial_detail = "no params found for policy binding" in result.stderr and name in result.stderr
        else:
            denial_detail = "exact compatibility approval" in result.stderr
        denied = result.returncode != 0 and denial_detail
        lab.check("red", description, denied and absent,
                  {"admission_denied": denied, "candidate_absent": absent})
        return denied and absent

    missing_ok = denied_case("Missing approval parameter is denied for the owned target", candidate,
                             missing_parameter=True)
    stale = deepcopy(candidate)
    stale["metadata"]["annotations"]["saf-lab.example/sequence-sha256"] = "stale-sequence"
    stale_ok = denied_case("Stale approved change sequence is denied without creating the target", stale)
    mismatching = deepcopy(candidate)
    mismatching["metadata"]["annotations"]["saf-lab.example/tuple-sha256"] = "different-tuple"
    mismatch_ok = denied_case("Mismatching component tuple is denied without creating the target", mismatching, apply=True)
    for _ in range(20):
        validation = lab.create(candidate, dry_run=True, allow_failure=True)
        if validation.returncode == 0:
            break
        time.sleep(1)
    else:
        lab.block("The exact synthetic approval was not accepted at native admission")

    applied = lab.create(candidate)
    lab.kubectl("rollout", "status", f"deployment/{target_resource}", "--timeout=90s", timeout=105)
    observed = json.loads(lab.kubectl("get", "deployment", target_resource, "-o", "json").stdout)
    for _ in range(20):
        marker = lab.kubectl("logs", f"deployment/{target_resource}").stdout.strip()
        if marker:
            break
        time.sleep(1)
    changed = lab.kubectl(
        "patch", "deployment", target_resource, "--type=merge", "-p",
        '{"metadata":{"annotations":{"saf-lab.example/matrix-sha256":"different-matrix"}}}',
        allow_failure=True,
    )
    retained = json.loads(lab.kubectl("get", "deployment", target_resource, "-o", "json").stdout)
    rejected_update = (
        changed.returncode != 0 and "exact compatibility approval" in changed.stderr
        and retained["metadata"]["uid"] == applied["metadata"]["uid"]
        and retained["metadata"]["annotations"]["saf-lab.example/matrix-sha256"] == digest
    )
    lab.check("green", "A stale receipt cannot change the admitted rollout", rejected_update,
              {"stale_update_denied_and_approved_receipt_kept": rejected_update})

    outcome = {
        "missing_approval_denied": missing_ok,
        "stale_sequence_denied": stale_ok,
        "mismatching_tuple_denied": mismatch_ok,
        "stale_resource_version_patch_denied_without_target_mutation": stale_precondition_ok,
        "applied_deployment_uid_observed": observed["metadata"]["uid"] == applied["metadata"]["uid"],
        "approved_matrix_digest_read_back":
            observed["metadata"]["annotations"]["saf-lab.example/matrix-sha256"] == digest,
        "approved_release_reached_live_workload": marker == release,
        "workload_ready": observed["status"].get("readyReplicas") == 1,
        "approved_tuple_sha256": tuple_digest,
        "approved_change_id": approved["change_id"],
        "approved_sequence_sha256": sequence_digest,
        "approved_checks_sha256": checks_digest,
    }
    lab.check("positive", "The exact matrix approval admits a live synthetic workload with the intended release",
              all(outcome.values()), outcome)
    return outcome


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

    permitted = _decide(matrix, after_block, permitted_change)
    if permitted["decision"] != "permit":
        lab.block("The fixture's compatible metadata-only change was not permitted")
    stale_snapshot = next(item for item in after_block["raw_owned_deployments"]
                          if item["metadata"]["name"] == _deployment_name(permitted_change["target_component"]))
    stale_version = stale_snapshot["metadata"]["resourceVersion"]
    stale_uid = stale_snapshot["metadata"]["uid"]
    stale_value = stale_snapshot["metadata"]["annotations"][COMPONENT_ANNOTATION]
    lab.kubectl(
        "patch", "deployment", stale_snapshot["metadata"]["name"], "--type=merge", "-p",
        json.dumps({"metadata": {"annotations": {"saf-lab.example/stale-probe": "advanced"}}}),
    )
    stale_patch = [
        {"op": "test", "path": "/metadata/resourceVersion", "value": stale_version},
        {"op": "add", "path": "/metadata/annotations/" + COMPONENT_ANNOTATION.replace("/", "~1"),
         "value": permitted_change["target_version"]},
    ]
    stale_result = lab.kubectl(
        "patch", "deployment", stale_snapshot["metadata"]["name"], "--type=json", "-p",
        json.dumps(stale_patch), allow_failure=True,
    )
    stale_retained = json.loads(lab.kubectl(
        "get", "deployment", stale_snapshot["metadata"]["name"], "-o", "json").stdout)
    stale_precondition_ok = (
        stale_result.returncode != 0
        and stale_retained["metadata"]["uid"] == stale_uid
        and stale_retained["metadata"]["annotations"][COMPONENT_ANNOTATION] == stale_value
        and stale_retained["metadata"]["annotations"].get("saf-lab.example/stale-probe") == "advanced"
    )
    lab.check("red", "A stale observed resourceVersion rejects the synthetic patch without changing its target field",
              stale_precondition_ok,
              {"stale_resource_version_rejected": stale_result.returncode != 0,
               "target_component_version_unchanged": stale_retained["metadata"]["annotations"].get(COMPONENT_ANNOTATION) == stale_value,
               "deployment_uid_preserved": stale_retained["metadata"]["uid"] == stale_uid})
    patch_baseline = _inventory(lab)
    permitted = apply_candidate(lab, matrix, patch_baseline, permitted_change)
    after = _inventory(lab)
    target_after = after["deployment_components"].get(permitted_change["target_component"], {})
    target_name = _deployment_name(permitted_change["target_component"])
    raw_before = {item.get("metadata", {}).get("name"): item
                  for item in patch_baseline["raw_owned_deployments"]}.get(target_name, {})
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

    native_gate = _live_gate(lab, matrix, permitted, stale_precondition_ok)
    evidence = {
        "native_admission_outcome": native_gate,
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
