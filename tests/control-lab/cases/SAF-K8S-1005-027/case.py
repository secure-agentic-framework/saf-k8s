"""Preserve scoped Kubernetes DRA metadata and labeled synthetic accelerator fixtures."""
import hashlib
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
CONTROL_ID = "SAF-K8S-1005-027"
NAMESPACE = "saf-test"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
CASE_LABEL = "saf-lab.example/control"
FIXTURE_LABEL = "saf-lab.example/fixture"
EVIDENCE_LABEL = "saf-lab.example/evidence"
FIXTURE_CONFIG = "saf-1005-027-accelerator-fixtures"
EVIDENCE_CONFIG = "saf-1005-027-retained-evidence"
DEVICE_CLASS = "saf-1005-027-mock-accelerator"
RESOURCE_SLICE = "saf-1005-027-mock-slice"
RESOURCE_CLAIM = "saf-1005-027-mock-claim"
MOCK_POD = "saf-1005-027-mock-workload"
ALLOCATION_POD = "saf-1005-027-allocation-observer"
MOCK_DRIVER = "mock.saf-lab.example"
FIXTURE_ID = "SYNTH-1005-027-ACCELERATOR-001"

SCOPE = (
    "One disposable Kubernetes v1.36.1 Kind cluster. Captures authorized Kubernetes API reads "
    "of one scheduler-allocated v1 ResourceClaim, its case-owned v1 ResourceSlice and DeviceClass, "
    "case-owned Pod and node identity, plus explicitly synthetic accelerator state and telemetry. "
    "The cluster has no accelerator hardware or DRA driver; the slice and device are inert mock "
    "metadata and no GPU calls, device load, attacks, host inspection, external targets, or real "
    "feeds are used. Proves scoped API evidence hashing, identity binding, and retained exact "
    "evidence after deletion of owned fixture sources. Does not prove forensic collection on a "
    "hardware node, actual driver telemetry, volatile hardware state, memory or disk acquisition, "
    "production authorization, external custody, retention, or incident reconstruction."
)


def _labels(*, evidence=False):
    result = {CASE_LABEL: CONTROL_ID}
    if evidence:
        result[EVIDENCE_LABEL] = "true"
    else:
        result[FIXTURE_LABEL] = "true"
    return result


def _object(api, kind, name, spec, *, namespace=None):
    metadata = {"name": name, "labels": _labels()}
    if namespace:
        metadata["namespace"] = namespace
    return {"apiVersion": api, "kind": kind, "metadata": metadata, "spec": spec}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(value):
    raw = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(raw).hexdigest()


def _read_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def _wait_allocation(lab):
    deadline = time.monotonic() + 60
    last = {}
    while time.monotonic() < deadline:
        last = _read_json(lab, "get", "resourceclaims", RESOURCE_CLAIM)
        allocation = last.get("status", {}).get("allocation", {})
        results = allocation.get("devices", {}).get("results", [])
        if results:
            if len(results) != 1 or results[0].get("driver") != MOCK_DRIVER:
                lab.block("Unexpected native allocation result for the synthetic DRA claim")
            return last
        time.sleep(0.5)
    lab.block(f"Kubernetes did not allocate the case-owned mock ResourceClaim; last status={last.get('status', {})}")


def _forbidden_key(value):
    forbidden = {"token", "password", "authorization", "bearer", "credential", "private_key",
                 "secret_data", "clientkeydata", "clientcertdata", "certificateauthoritydata"}
    if isinstance(value, dict):
        return any(str(key).lower() in forbidden or _forbidden_key(child) for key, child in value.items())
    if isinstance(value, list):
        return any(_forbidden_key(child) for child in value)
    return False


def _validate(bundle):
    artifacts = bundle.get("artifacts")
    digests = bundle.get("sha256")
    expected_artifacts = {"cluster_identity", "resource_slice", "resource_claim", "device_class",
                          "allocation_pod", "mock_workload", "synthetic_accelerator_telemetry"}
    if not isinstance(artifacts, dict) or set(artifacts) != expected_artifacts:
        return {"accepted": False, "reason": "required_scoped_artifact_set_incomplete"}
    if bundle.get("control_id") != CONTROL_ID or bundle.get("secrets_included") is not False:
        return {"accepted": False, "reason": "control_identity_or_secret_assertion_invalid"}
    if not isinstance(digests, dict) or set(digests) != expected_artifacts:
        return {"accepted": False, "reason": "artifact_digest_set_incomplete"}
    for name, artifact in artifacts.items():
        if not isinstance(artifact, (dict, list)) or not artifact or _forbidden_key(artifact):
            return {"accepted": False, "reason": "empty_or_sensitive_artifact"}
        if digests.get(name) != _sha256(artifact):
            return {"accepted": False, "reason": "artifact_digest_mismatch"}
    identity = artifacts["cluster_identity"]
    if (identity.get("control_id") != CONTROL_ID or identity.get("kubernetes_version") != "v1.36.1"
            or identity.get("node_image") != NODE_IMAGE or identity.get("namespace") != NAMESPACE):
        return {"accepted": False, "reason": "cluster_or_case_identity_mismatch"}
    claim = artifacts["resource_claim"]
    allocation = claim.get("status", {}).get("allocation", {}).get("devices", {}).get("results", [])
    if len(allocation) != 1 or allocation[0].get("driver") != MOCK_DRIVER:
        return {"accepted": False, "reason": "native_dra_allocation_missing_or_unexpected"}
    return {"accepted": True, "reason": "scoped_evidence_identity_and_digests_verified"}


def _delete_owned_source(lab, resource, name, *, cluster_scoped=False):
    args = ["get", resource, name]
    if cluster_scoped:
        args.extend(["--namespace="])
    obj = _read_json(lab, *args)
    labels = obj.get("metadata", {}).get("labels", {})
    if labels.get(CASE_LABEL) != CONTROL_ID or labels.get(FIXTURE_LABEL) != "true":
        lab.block(f"Refusing to delete unowned fixture source {resource}/{name}")
    uid = obj.get("metadata", {}).get("uid")
    delete_args = ["delete", resource, name, "--wait=true"]
    if cluster_scoped:
        delete_args.append("--namespace=")
    lab.kubectl(*delete_args)
    remaining = lab.kubectl("get", resource, name, "--ignore-not-found", "-o", "name")
    if remaining.stdout.strip():
        lab.block(f"Owned fixture source remains after deletion: {resource}/{name}")
    return {"kind": obj.get("kind"), "name": name, "uid": uid, "removed": True}


def run(lab):
    fixture = json.loads((FIXTURES / "accelerator-telemetry.json").read_text(encoding="utf-8"))
    if fixture.get("fixture_id") != FIXTURE_ID or fixture.get("evidence_class") != "synthetic_fixture":
        lab.block("The accelerator fixture identity or synthetic evidence label is invalid")

    version = _read_json(lab, "version")
    server_version = version.get("serverVersion", {})
    nodes = _read_json(lab, "get", "nodes").get("items", [])
    if server_version.get("gitVersion") != "v1.36.1" or len(nodes) != 1:
        lab.block("The case requires the disposable Kubernetes v1.36.1 single-node Kind cluster")
    node = nodes[0]
    node_name = node["metadata"]["name"]
    namespace = _read_json(lab, "get", "namespace", NAMESPACE)

    fixture_config = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": FIXTURE_CONFIG, "namespace": NAMESPACE, "labels": _labels()},
        "immutable": True,
        "data": {"accelerator-telemetry.json": json.dumps(fixture, sort_keys=True)},
    }
    created_fixture = lab.create(fixture_config)

    resource_slice = _object("resource.k8s.io/v1", "ResourceSlice", RESOURCE_SLICE, {
        "driver": MOCK_DRIVER,
        "nodeName": node_name,
        "pool": {"name": "synthetic-pool", "generation": 1, "resourceSliceCount": 1},
        "devices": [{
            "name": "mock-accelerator-001",
            "attributes": {f"{MOCK_DRIVER}/type": {"string": "accelerator"},
                           f"{MOCK_DRIVER}/evidence": {"string": "synthetic-fixture"}},
            "capacity": {f"{MOCK_DRIVER}/memory": {"value": "1Gi"}},
        }],
    })
    created_slice = lab.create(resource_slice)
    device_class = _object("resource.k8s.io/v1", "DeviceClass", DEVICE_CLASS, {
        "selectors": [{"cel": {"expression": (
            f"device.driver == '{MOCK_DRIVER}' && "
            f"device.attributes['{MOCK_DRIVER}'].type == 'accelerator'"
        )}}],
    })
    created_class = lab.create(device_class)
    claim = _object("resource.k8s.io/v1", "ResourceClaim", RESOURCE_CLAIM, {
        "devices": {"requests": [{"name": "mock-accelerator", "exactly": {
            "deviceClassName": DEVICE_CLASS, "allocationMode": "ExactCount", "count": 1,
        }}]},
    }, namespace=NAMESPACE)
    created_claim = lab.create(claim)

    workload = (FIXTURES / "workload.py").read_text(encoding="utf-8")
    workload_pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": MOCK_POD, "namespace": NAMESPACE, "labels": _labels()},
        "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "cpu-only-mock", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "-c", workload],
                "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]}},
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
            }],
        },
    }
    created_workload = lab.create(workload_pod)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        observed_pod = _read_json(lab, "get", "pod", MOCK_POD)
        phase = observed_pod.get("status", {}).get("phase")
        if phase in {"Succeeded", "Failed"}:
            break
        time.sleep(1)
    if phase != "Succeeded":
        lab.block("CPU-only fixture workload did not complete; raw pod logs are not accepted")
    logs = lab.kubectl("logs", MOCK_POD, "-c", "cpu-only-mock").stdout
    try:
        log_records = [json.loads(line) for line in logs.splitlines() if line.strip()]
    except json.JSONDecodeError:
        lab.block("Mock workload output was not structured synthetic telemetry")
    if log_records != fixture.get("telemetry"):
        lab.block("Observed mock workload output does not match its case-owned telemetry fixture")

    allocation_pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": ALLOCATION_POD, "namespace": NAMESPACE, "labels": _labels()},
        "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "resourceClaims": [{"name": "mock-accelerator", "resourceClaimName": RESOURCE_CLAIM}],
            "containers": [{
                "name": "allocation-observer", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "-c", "print('synthetic DRA allocation observer')"],
                "resources": {"claims": [{"name": "mock-accelerator"}],
                              "requests": {"cpu": "10m", "memory": "16Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
                "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]}},
            }],
        },
    }
    created_allocation_pod = lab.create(allocation_pod)
    allocated_claim = _wait_allocation(lab)
    observed_slice = _read_json(lab, "get", "resourceslices", RESOURCE_SLICE, "--namespace=")
    observed_class = _read_json(lab, "get", "deviceclasses", DEVICE_CLASS, "--namespace=")
    observed_allocation_pod = _read_json(lab, "get", "pod", ALLOCATION_POD)
    observed_fixture = _read_json(lab, "get", "configmap", FIXTURE_CONFIG)
    if (observed_fixture.get("metadata", {}).get("uid") != created_fixture.get("metadata", {}).get("uid")
            or json.loads(observed_fixture.get("data", {}).get("accelerator-telemetry.json", "{}")) != fixture):
        lab.block("Synthetic telemetry fixture did not match the case-owned API readback")
    if (allocated_claim.get("metadata", {}).get("uid") != created_claim.get("metadata", {}).get("uid")
            or observed_slice.get("metadata", {}).get("uid") != created_slice.get("metadata", {}).get("uid")
            or observed_class.get("metadata", {}).get("uid") != created_class.get("metadata", {}).get("uid")
            or observed_pod.get("metadata", {}).get("uid") != created_workload.get("metadata", {}).get("uid")
            or observed_allocation_pod.get("metadata", {}).get("uid") != created_allocation_pod.get("metadata", {}).get("uid")):
        lab.block("Observed API object identity did not match the object created by this case")

    allocation_results = allocated_claim["status"]["allocation"]["devices"]["results"]
    if allocation_results[0].get("device") != "mock-accelerator-001":
        lab.block("Native allocation did not resolve to the expected inert mock device")
    artifacts = {
        "cluster_identity": {
            "control_id": CONTROL_ID, "cluster_name": lab.cluster, "kubernetes_version": "v1.36.1",
            "node_image": NODE_IMAGE, "namespace": NAMESPACE,
            "namespace_uid": namespace.get("metadata", {}).get("uid"),
            "node": {"name": node_name, "uid": node.get("metadata", {}).get("uid"),
                     "kubelet_version": node.get("status", {}).get("nodeInfo", {}).get("kubeletVersion")},
            "python_image": PYTHON_IMAGE,
        },
        "resource_slice": observed_slice,
        "resource_claim": allocated_claim,
        "device_class": observed_class,
        "allocation_pod": observed_allocation_pod,
        "mock_workload": {"pod": observed_pod, "logs": log_records,
                          "fixture_configmap_uid": observed_fixture["metadata"]["uid"]},
        "synthetic_accelerator_telemetry": fixture,
    }
    bundle = {
        "control_id": CONTROL_ID,
        "evidence_class": "scoped_api_capture_with_explicit_synthetic_hardware_fixture",
        "captured_from": "authorized Kubernetes API reads and case-owned ConfigMap fixture",
        "secrets_included": False,
        "actual_hardware_or_driver_observed": False,
        "external_targets_contacted": False,
        "artifacts": artifacts,
        "sha256": {name: _sha256(value) for name, value in artifacts.items()},
    }

    incomplete = json.loads(json.dumps(bundle))
    incomplete["artifacts"].pop("synthetic_accelerator_telemetry")
    incomplete["sha256"].pop("synthetic_accelerator_telemetry")
    red_missing = _validate(incomplete)
    lab.check("red", "Evidence validation rejects a missing synthetic telemetry artifact",
              red_missing == {"accepted": False, "reason": "required_scoped_artifact_set_incomplete"},
              {"validator": red_missing})
    tampered = json.loads(json.dumps(bundle))
    tampered["artifacts"]["resource_claim"]["status"]["allocation"]["devices"]["results"][0]["device"] = "changed-device"
    red_digest = _validate(tampered)
    lab.check("red", "Evidence validation rejects changed native allocation evidence",
              red_digest == {"accepted": False, "reason": "artifact_digest_mismatch"},
              {"validator": red_digest})
    green = _validate(bundle)
    lab.check("green", "Complete scoped evidence passes case identity, allocation and digest checks",
              green == {"accepted": True, "reason": "scoped_evidence_identity_and_digests_verified"},
              {"validator": green, "artifact_count": len(artifacts), "all_artifact_digests_verified": True})

    evidence_bytes = (json.dumps(bundle, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    evidence_digest = _sha256(evidence_bytes)
    evidence_obj = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": EVIDENCE_CONFIG, "namespace": NAMESPACE, "labels": _labels(evidence=True)},
        "immutable": True,
        "data": {"bundle.json": evidence_bytes.decode("utf-8"), "bundle.sha256": evidence_digest},
    }
    created_evidence = lab.create(evidence_obj)
    if created_evidence.get("immutable") is not True:
        lab.block("Evidence store did not accept immutable retention metadata")

    removed = []
    for resource, name, cluster_scoped in (
        ("pods", MOCK_POD, False), ("pods", ALLOCATION_POD, False),
        ("configmaps", FIXTURE_CONFIG, False), ("resourceclaims", RESOURCE_CLAIM, False),
        ("resourceslices", RESOURCE_SLICE, True), ("deviceclasses", DEVICE_CLASS, True),
    ):
        removed.append(_delete_owned_source(lab, resource, name, cluster_scoped=cluster_scoped))

    retained = _read_json(lab, "get", "configmap", EVIDENCE_CONFIG)
    retained_raw = retained.get("data", {}).get("bundle.json", "").encode("utf-8")
    retained_bundle = json.loads(retained_raw)
    retained_valid = (
        retained.get("metadata", {}).get("uid") == created_evidence.get("metadata", {}).get("uid")
        and retained.get("immutable") is True
        and retained.get("metadata", {}).get("labels", {}).get(EVIDENCE_LABEL) == "true"
        and retained_raw == evidence_bytes
        and retained.get("data", {}).get("bundle.sha256") == evidence_digest
        and _sha256(retained_raw) == evidence_digest
        and _validate(retained_bundle)["accepted"]
    )
    lab.check("positive", "Exact immutable evidence remains readable after owned fixture sources are removed",
              retained_valid and len(removed) == 6,
              {"retained_evidence_uid_matches": retained.get("metadata", {}).get("uid") == created_evidence.get("metadata", {}).get("uid"),
               "retained_bytes_exact": retained_raw == evidence_bytes, "retained_digest_matches": _sha256(retained_raw) == evidence_digest,
               "removed_owned_sources": [{"kind": row["kind"], "name": row["name"]} for row in removed],
               "artifact_count": len(artifacts)})

    raw_evidence = {
        "control_id": CONTROL_ID, "scope": SCOPE, "bundle": bundle,
        "retained_store": {"namespace": NAMESPACE, "name": EVIDENCE_CONFIG,
                           "uid": retained.get("metadata", {}).get("uid"),
                           "sha256": evidence_digest, "exact_bytes_verified": retained_raw == evidence_bytes},
        "owned_fixture_sources_removed": removed,
        "checks": lab.checks,
        "secrets_included": False, "actual_hardware_or_driver_observed": False,
        "external_targets_contacted": False,
    }
    (lab.evidence / "forensic-acquisition.raw.json").write_text(
        json.dumps(raw_evidence, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
