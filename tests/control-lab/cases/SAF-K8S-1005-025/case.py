"""Acquire bounded synthetic Kubernetes evidence and reject incomplete evidence packages."""
import hashlib
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
CONTROL_ID = "SAF-K8S-1005-025"
NAMESPACE = "saf-test"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
CONFIG_NAME = "saf-1005-025-fixtures"
POD_NAME = "saf-1005-025-mock-workload"
CASE_LABEL = "saf-lab.example/control"
FIXTURE_LABEL = "saf-lab.example/fixture"
REQUIRED_ARTIFACTS = {
    "container_logs", "api_audit_observations", "node_metadata", "fixture_network_telemetry",
}
AUDIT_DIR = "/var/log/kubernetes/saf-acquisition"
AUDIT_LOG = f"{AUDIT_DIR}/audit.log"
SCOPE = (
    "One disposable Kubernetes v1.36.1 Kind cluster, a tokenless Pod, its real fixture logs, "
    "allowlisted node metadata, Kubernetes metadata-only audit events for the exact case "
    "objects, and connection metadata from one loopback fixture TCP exchange. Missing and "
    "digest-mismatched artifacts fail manifest validation. No production forensic capture, "
    "memory/disk acquisition, CNI-wide flows, packet contents, external traffic, retention "
    "or organization-wide procedures are validated."
)


def prepare_kind(lab, temporary):
    policy = temporary / "audit-policy.yaml"
    audit = temporary / "audit"
    audit.mkdir(mode=0o700)
    policy.write_text(
        "apiVersion: audit.k8s.io/v1\nkind: Policy\nomitStages: [RequestReceived]\nrules:\n"
        "  - level: Metadata\n"
        f"    namespaces: [{NAMESPACE}]\n"
        "    verbs: [create, get]\n"
        '    resources: [{group: "", resources: [configmaps, pods, pods/log]}]\n'
        "  - level: None\n"
    )
    lab.fixture_audit = audit / "audit.log"
    config = temporary / "kind-audit.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: {json.dumps(str(policy))}
        containerPath: /etc/kubernetes/saf-audit-policy.yaml
        readOnly: true
      - hostPath: {json.dumps(str(audit))}
        containerPath: {AUDIT_DIR}
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        - name: audit-policy-file
          value: /etc/kubernetes/saf-audit-policy.yaml
        - name: audit-log-path
          value: {AUDIT_LOG}
      extraVolumes:
        - name: saf-audit-policy
          hostPath: /etc/kubernetes/saf-audit-policy.yaml
          mountPath: /etc/kubernetes/saf-audit-policy.yaml
          readOnly: true
          pathType: File
        - name: saf-audit-output
          hostPath: {AUDIT_DIR}
          mountPath: {AUDIT_DIR}
          readOnly: false
          pathType: Directory
""")
    return config


def collect_audit(lab):
    expected = {
        ("create", "configmaps", "", CONFIG_NAME, 201),
        ("create", "pods", "", POD_NAME, 201),
        ("get", "pods", "log", POD_NAME, 200),
    }
    selected = {}
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if lab.fixture_audit.is_file():
            for line in lab.fixture_audit.read_text().splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ref = event.get("objectRef", {})
                key = (event.get("verb"), ref.get("resource"), ref.get("subresource", ""),
                       ref.get("name"), event.get("responseStatus", {}).get("code"))
                if (key in expected and ref.get("namespace") == NAMESPACE
                        and event.get("stage") == "ResponseComplete"):
                    if (event.get("level") != "Metadata"
                            or any(event.get(field) is not None for field in ("requestObject", "responseObject"))
                            or not event.get("auditID")):
                        lab.block(f"Unexpected audit schema for {key[0]} {key[1]}/{key[2]}")
                    selected[key] = {"audit_id": event["auditID"], "verb": key[0], "resource": key[1],
                                     "subresource": key[2], "name": key[3], "status_code": key[4]}
            if expected <= selected.keys():
                return [selected[key] for key in sorted(expected)]
        time.sleep(0.3)
    lab.block("Missing metadata-only audit observations for the exact owned requests")



def _hash(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _owned_labels():
    return {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "true"}


def _pod(config_name):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": POD_NAME, "namespace": NAMESPACE, "labels": _owned_labels()},
        "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "mock-workload", "image": PYTHON_IMAGE,
                "imagePullPolicy": "IfNotPresent", "command": ["python", "-B", "/fixture/workload.py"],
                "securityContext": {"readOnlyRootFilesystem": True,
                                    "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]}},
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
                "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
            }],
            "volumes": [{"name": "fixture", "configMap": {"name": config_name}}],
        },
    }


def _wait_for_pod(lab):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        pod = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pod", POD_NAME, "-o", "json").stdout)
        phase = pod.get("status", {}).get("phase")
        if phase in {"Succeeded", "Failed"}:
            break
        time.sleep(1)
    else:
        lab.block("Mock workload did not reach a terminal state")
    status = pod.get("status", {})
    terminated = status.get("containerStatuses", [{}])[0].get("state", {}).get("terminated", {})
    if phase != "Succeeded" or terminated.get("exitCode") != 0:
        lab.block("Mock workload did not complete successfully; raw container diagnostics are excluded")
    return pod, terminated


def _collect_node_metadata(lab):
    response = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)
    nodes = []
    for node in response.get("items", []):
        info = node.get("status", {}).get("nodeInfo", {})
        nodes.append({
            "name": node.get("metadata", {}).get("name"),
            "uid": node.get("metadata", {}).get("uid"),
            "kubelet_version": info.get("kubeletVersion"),
            "container_runtime_version": info.get("containerRuntimeVersion"),
            "operating_system": info.get("operatingSystem"),
            "architecture": info.get("architecture"),
            "kernel_version": info.get("kernelVersion"),
        })
    if not nodes or any(not all(item.values()) for item in nodes):
        lab.block("Node metadata evidence is incomplete")
    return nodes


def _validate_package(package):
    artifacts = package.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != REQUIRED_ARTIFACTS:
        return {"accepted": False, "reason": "required_artifact_set_incomplete_or_unexpected"}
    if package.get("scope_id") != CONTROL_ID or package.get("secrets_included") is not False:
        return {"accepted": False, "reason": "scope_or_secret_assertion_invalid"}
    if package.get("actual_api_server_audit_log") is not True:
        return {"accepted": False, "reason": "native_audit_evidence_required"}
    expected = package.get("sha256", {})
    if set(expected) != REQUIRED_ARTIFACTS:
        return {"accepted": False, "reason": "artifact_digest_set_incomplete_or_unexpected"}
    for name, value in artifacts.items():
        if (not isinstance(value, (dict, list)) or not value
                or _contains_sensitive_field(value) or expected.get(name) != _hash(value)):
            return {"accepted": False, "reason": "artifact_digest_mismatch_or_empty"}
    return {"accepted": True, "reason": "complete_synthetic_package_integrity_verified"}


def _contains_sensitive_field(value):
    forbidden = {"token", "password", "authorization", "bearer", "credential",
                 "private_key", "secret_data", "request_body", "raw_request", "actor"}
    if isinstance(value, dict):
        return any(str(key).lower() in forbidden or _contains_sensitive_field(child)
                   for key, child in value.items())
    if isinstance(value, list):
        return any(_contains_sensitive_field(child) for child in value)
    return False


def run(lab):
    workload_fixture = json.loads((FIXTURES / "workload-log.json").read_text())
    if workload_fixture.get("fixture_id") != "SYNTH-1005-025-WORKLOAD-001":
        lab.block("Unexpected workload fixture identity")
    config_obj = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": CONFIG_NAME, "namespace": NAMESPACE, "labels": _owned_labels()},
        "immutable": True,
        "data": {"workload-log.json": json.dumps(workload_fixture, sort_keys=True),
                 "workload.py": (FIXTURES / "workload.py").read_text()},
    }
    config = lab.create(config_obj)
    readback = json.loads(lab.kubectl("-n", NAMESPACE, "get", "configmap", CONFIG_NAME, "-o", "json").stdout)
    if (readback.get("metadata", {}).get("uid") != config.get("metadata", {}).get("uid")
            or readback.get("immutable") is not True
            or json.loads(readback.get("data", {}).get("workload-log.json", "{}")) != workload_fixture):
        lab.block("Case-owned immutable workload fixture did not pass Kubernetes API readback")

    created_pod = lab.create(_pod(CONFIG_NAME))
    pod, terminated = _wait_for_pod(lab)
    metadata = pod.get("metadata", {})
    if metadata.get("uid") != created_pod.get("metadata", {}).get("uid"):
        lab.block("Observed Pod UID does not match the created case-owned Pod")
    raw_logs = lab.kubectl("-n", NAMESPACE, "logs", POD_NAME, "-c", "mock-workload").stdout
    try:
        log_records = [json.loads(line) for line in raw_logs.splitlines() if line.strip()]
    except json.JSONDecodeError:
        lab.block("Mock workload logs were not complete JSON records")
    flow = log_records[-1] if log_records else {}
    log_records = log_records[:-1]
    expected_flow = {"kind": "fixture-connection", "protocol": "tcp", "source": "127.0.0.1",
                     "destination": "127.0.0.1", "requests": 1, "responses": 1,
                     "marker_verified": True}
    if flow != expected_flow:
        lab.block("Missing exact loopback acquisition flow receipt")
    if log_records != workload_fixture.get("records"):
        lab.block("Observed mock container logs do not exactly match the case-owned fixture")
    container_logs = {
        "source": "Kubernetes API pod log subresource",
        "pod": POD_NAME, "pod_uid": metadata["uid"],
        "container": "mock-workload", "exit_code": terminated.get("exitCode"),
        "records": log_records,
    }

    node_metadata = _collect_node_metadata(lab)
    observed_nodes = [node for node in node_metadata if node["name"] == pod.get("spec", {}).get("nodeName")]
    if len(observed_nodes) != 1:
        lab.block("Fixture Pod assignment does not match the captured Node metadata")
    api_audit_observations = collect_audit(lab)
    package = {
        "scope_id": CONTROL_ID,
        "actual_api_server_audit_log": True,
        "secrets_included": False,
        "artifacts": {
            "container_logs": container_logs,
            "api_audit_observations": api_audit_observations,
            "node_metadata": node_metadata,
            "fixture_network_telemetry": flow,
        },
    }
    package["sha256"] = {name: _hash(value) for name, value in package["artifacts"].items()}

    incomplete = dict(package)
    incomplete["artifacts"] = dict(package["artifacts"])
    incomplete["artifacts"].pop("fixture_network_telemetry")
    incomplete["sha256"] = dict(package["sha256"])
    incomplete["sha256"].pop("fixture_network_telemetry")
    red = _validate_package(incomplete)
    lab.check(
        "red", "The acquisition validator rejects a package missing the fixture connection record",
        red["accepted"] is False and red["reason"] == "required_artifact_set_incomplete_or_unexpected",
        {"validator": red, "missing_artifact": "fixture_network_telemetry"},
    )

    changed = {**package, "artifacts": {**package["artifacts"],
                                       "fixture_network_telemetry": {**flow, "responses": 0}}}
    tampered = _validate_package(changed)
    lab.check("red", "The unchanged manifest rejects a modified connection record",
              not tampered["accepted"] and tampered["reason"] == "artifact_digest_mismatch_or_empty",
              tampered)
    green = _validate_package(package)
    lab.check(
        "green", "The validator accepts all four complete synthetic artifact classes with matching hashes",
        green["accepted"] is True and green["reason"] == "complete_synthetic_package_integrity_verified",
        {"validator": green, "artifact_classes": sorted(package["artifacts"]),
         "all_sha256_match": True},
    )

    node_versions = sorted({row["kubelet_version"] for row in node_metadata})
    positive = (
        container_logs["records"] == workload_fixture["records"]
        and container_logs["pod_uid"] == metadata["uid"]
        and node_versions == ["v1.36.1"]
        and len(api_audit_observations) == 3
        and flow == expected_flow
    )
    lab.check(
        "positive", "The evidence binds the successful fixture logs, API actions, node and loopback exchange",
        positive,
        {"pod_uid_matches_readback": True, "kubelet_versions": node_versions,
         "metadata_audit_events": len(api_audit_observations), "fixture_connection": flow},
    )

    evidence = {
        "control_id": CONTROL_ID,
        "scope": SCOPE,
        "scope_id": CONTROL_ID,
        "artifact_bundle": package,
        "checks": lab.checks,
        "acquisition_rejected_if_incomplete": red["accepted"] is False,
        "secrets_included": False,
        "external_targets_contacted": False,
        "actual_api_server_audit_log_collected": True,
        "only_owned_temporary_audit_mounts": True,
        "packet_capture_performed": False,
    }
    (lab.evidence / "forensic-acquisition.raw.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
