"""Read-only telemetry and synthetic rule checks for SAF-K8S-1001-012."""
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
CONTROL_ID = "SAF-K8S-1001-012"
NAMESPACE = "saf-test"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
POD = "saf-1001-012-mock"
POD_COMPARATOR = "saf-1001-012-comparator"
CONFIG = "saf-1001-012-fixture"
CASE_LABEL = "saf-lab.example/control"
FIXTURE_LABEL = "saf-lab.example/fixture"
RULES = (
    "unexpected_inferenceservice_create",
    "gpu_without_training_job",
    "training_job_changed_by_non_owner",
    "inference_request_rate_spike",
    "large_model_storage_egress",
    "audit_policy_configmap_changed",
)
SCOPE = (
    "One disposable single-node Kind Kubernetes v1.36.1 cluster. Reads metadata for two exact case-owned "
    "tokenless mock Pods, their case-owned ConfigMap, assigned Node, fixed JSON log lines, and namespaced "
    "Kubernetes Events. Exercises six explicitly specified decisions on "
    "static synthetic audit-shaped records and fabricated benign counters. No SIEM is connected, no AI/GPU "
    "runtime exists, no KServe/API extension is installed, and no live attack or external traffic is used. "
    "This validates deterministic rule logic and a bounded local Pod/log/Event UID join only; no independent "
    "monitoring product or deployed SIEM is connected."
)


def create(lab, obj):
    return json.loads(lab.kubectl("create", "-f", "-", "-o", "json", payload=json.dumps(obj)).stdout)


def labels():
    return {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "true"}


def pod(config_name, name=POD):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": labels()},
        "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "mock-workload", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "/fixture/workload.py"],
                "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]}},
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
                "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
            }],
            "volumes": [{"name": "fixture", "configMap": {"name": config_name}}],
        },
    }


def detect(record, thresholds, approved):
    rule = record.get("rule")
    if rule == "unexpected_inferenceservice_create":
        return record.get("verb") == "create" and record.get("resource") == "inferenceservices" and record.get("api_group") == "serving.kserve.io" and record.get("principal") not in approved
    if rule == "gpu_without_training_job":
        samples = record.get("gpu_percent_samples", [])
        return len(samples) >= thresholds["gpu_consecutive_samples"] and all(
            isinstance(value, (int, float)) and value >= thresholds["gpu_percent"] for value in samples[-thresholds["gpu_consecutive_samples"]:]
        ) and record.get("active_training_jobs") == 0
    if rule == "training_job_changed_by_non_owner":
        return record.get("verb") in {"patch", "update"} and record.get("resource") == "jobs" and record.get("api_group") == "batch" and (record.get("principal") != record.get("owner") or record.get("principal") not in approved)
    if rule == "inference_request_rate_spike":
        return record.get("kind") == "counter" and record.get("requests_per_minute", 0) > thresholds["inference_requests_per_minute"]
    if rule == "large_model_storage_egress":
        return record.get("kind") == "counter" and record.get("egress_bytes_per_minute", 0) > thresholds["model_egress_bytes_per_minute"] and not record.get("approved_window", False)
    if rule == "audit_policy_configmap_changed":
        return record.get("verb") in {"patch", "update", "delete"} and record.get("resource") == "configmaps" and record.get("namespace") == "kube-system" and "audit" in record.get("object", "").lower()
    return False


def correlate_owned_pod_events(pod_signal, event_signals):
    """Join the native Pod metadata and Event stream on the immutable Pod UID."""
    labels = pod_signal.get("labels", {})
    if (pod_signal.get("namespace") != NAMESPACE
            or labels.get(CASE_LABEL) != CONTROL_ID
            or labels.get(FIXTURE_LABEL) != "true"):
        return []
    return [event for event in event_signals
            if event.get("regarding_uid") == pod_signal.get("uid")]


def collect_native(lab, created_uid, config_uid, pod_name=POD):
    deadline = time.monotonic() + 100
    pod_data = None
    while time.monotonic() < deadline:
        pod_data = json.loads(lab.kubectl("get", "pod", pod_name, "-o", "json").stdout)
        phase = pod_data.get("status", {}).get("phase")
        if phase in {"Succeeded", "Failed"}:
            break
        time.sleep(1)
    else:
        lab.block("Tokenless case-owned Pod did not reach a terminal phase")
    status = pod_data.get("status", {})
    terminated = status.get("containerStatuses", [{}])[0].get("state", {}).get("terminated", {})
    if (pod_data.get("metadata", {}).get("uid") != created_uid or phase != "Succeeded"
            or terminated.get("exitCode") != 0):
        lab.block("Case-owned Pod did not complete with the expected UID and zero exit code")
    log = lab.kubectl("logs", pod_name, "-c", "mock-workload").stdout
    lines = [json.loads(line) for line in log.splitlines() if line.strip()]
    expected = {"event": "mock_workload_ready", "fixture_id": "SYNTH-SAF-K8S-1001-012-WORKLOAD-001",
                "network_calls": 0, "secret_values": 0}
    if lines != [expected]:
        lab.block("Mock workload log did not match its fixed benign fixture record")

    raw_events = json.loads(lab.kubectl(
        "get", "events", "--field-selector", f"involvedObject.name={pod_name}", "-o", "json",
    ).stdout).get("items", [])
    events = []
    for event in raw_events:
        ref = event.get("regarding") or event.get("involvedObject") or {}
        if ref.get("uid") != created_uid:
            continue
        events.append({
            "type": event.get("type"), "reason": event.get("reason"),
            "action": event.get("action"), "count": event.get("series", {}).get("count", event.get("count", 1)),
            "reporting_controller": event.get("reportingController") or event.get("source", {}).get("component"),
            "regarding_uid": ref.get("uid"),
        })
    if not events:
        lab.block("No real Kubernetes Event was observed for the case-owned Pod")
    node_response = json.loads(lab.kubectl("get", "node", pod_data.get("spec", {}).get("nodeName"), "-o", "json").stdout)
    info = node_response.get("status", {}).get("nodeInfo", {})
    node = {"name": node_response.get("metadata", {}).get("name"),
            "uid": node_response.get("metadata", {}).get("uid"),
            "kubelet_version": info.get("kubeletVersion"),
            "container_runtime_version": info.get("containerRuntimeVersion"),
            "architecture": info.get("architecture")}
    if not all(node.values()):
        lab.block("Allowlisted Node metadata was incomplete")
    return {
        "source": "Kubernetes API read-only get events/pod/node plus pod log subresource",
        "pod": {"name": pod_name, "namespace": NAMESPACE, "uid": created_uid, "phase": phase,
                "labels": pod_data.get("metadata", {}).get("labels", {}),
                "service_account_token_mounted": False, "image": PYTHON_IMAGE},
        "fixture_configmap": {"name": CONFIG, "uid": config_uid, "immutable": True},
        "node": node, "events": sorted(events, key=lambda item: (item.get("reason") or "", item.get("action") or "")),
        "workload_log": expected,
    }


def run(lab):
    fixture = json.loads((FIXTURES / "telemetry.json").read_text(encoding="utf-8"))
    if (fixture.get("fixture_id") != "SYNTH-SAF-K8S-1001-012-TELEMETRY-001"
            or fixture.get("fixture_kind") != "static-benign-defensive-detection-validation"
            or any(row.get("fixture_only") is not True for row in fixture.get("records", []))):
        lab.block("Static synthetic fixture identity or benign-only marker is invalid")
    by_rule = {rule: [row for row in fixture["records"] if row.get("rule") == rule] for rule in RULES}
    if any(len(rows) != 2 for rows in by_rule.values()):
        lab.block("Each rule must have exactly one synthetic alert case and one benign control")
    thresholds = fixture["thresholds"]
    approved = set(fixture["approved_identities"])
    outcomes = {}
    for rule, rows in by_rule.items():
        observed = {row["id"]: detect(row, thresholds, approved) for row in rows}
        outcomes[rule] = observed
        lab.check("red", f"Synthetic positive for {rule} triggers its rule",
                  observed[rows[0]["id"]] is True,
                  {"rule": rule, "fixture_id": rows[0]["id"], "alert": observed[rows[0]["id"]]})
        lab.check("green", f"Approved or benign control for {rule} does not trigger",
                  observed[rows[1]["id"]] is False,
                  {"rule": rule, "fixture_id": rows[1]["id"], "alert": observed[rows[1]["id"]]})

    config_obj = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": CONFIG, "namespace": NAMESPACE, "labels": labels()},
        "immutable": True,
        "data": {"workload.py": (FIXTURES / "workload.py").read_text(encoding="utf-8"),
                 "fixture-id": fixture["fixture_id"]},
    }
    config = create(lab, config_obj)
    created = create(lab, pod(CONFIG))
    actual = collect_native(lab, created["metadata"]["uid"], config["metadata"]["uid"])
    config_readback = json.loads(lab.kubectl("get", "configmap", CONFIG, "-o", "json").stdout)
    if config_readback.get("metadata", {}).get("uid") != config.get("metadata", {}).get("uid"):
        lab.block("Case-owned fixture ConfigMap UID did not match Kubernetes readback")
    lab.check("positive", "Read-only native telemetry is bound to the case-owned Pod and Node",
              actual["pod"]["uid"] == created["metadata"]["uid"]
              and bool(actual["events"]) and actual["node"]["kubelet_version"] == "v1.36.1"
              and actual["workload_log"]["network_calls"] == 0,
              {"pod_uid_matches_create": True, "owned_pod_event_observed": bool(actual["events"]),
               "node_version": actual["node"]["kubelet_version"],
               "workload_log_fixture": actual["workload_log"]["fixture_id"]})

    comparator_created = create(lab, pod(CONFIG, name=POD_COMPARATOR))
    comparator = collect_native(lab, comparator_created["metadata"]["uid"],
                                config["metadata"]["uid"], POD_COMPARATOR)

    pod_signal = actual["pod"]
    observed_events = [*actual["events"], *comparator["events"]]
    unmatched_event = dict(actual["events"][0])
    unmatched_event["regarding_uid"] = "SYNTH-UNMATCHED-POD-UID"
    matched = correlate_owned_pod_events(pod_signal, [*actual["events"], unmatched_event])
    wrong_scope = {**pod_signal, "namespace": "outside-fixture"}
    excluded = correlate_owned_pod_events(wrong_scope, actual["events"])
    correlation_result = {
        "rule": "owned_pod_event_uid_correlation",
        "pod_source": "Kubernetes Pod metadata read",
        "event_source": "Kubernetes Events API read",
        "bound_native_events_observed": bool(matched),
        "unmatched_uid_excluded": unmatched_event not in matched,
        "out_of_scope_pod_excluded": not excluded,
        "case_label_scoped": pod_signal["labels"].get(CASE_LABEL) == CONTROL_ID,
        "fixture_label_scoped": pod_signal["labels"].get(FIXTURE_LABEL) == "true",
    }
    correlation_ok = bool(matched) and matched == actual["events"] and not excluded
    lab.check("correlation", "The owned Pod and Event metadata join on UID; an unmatched UID does not correlate",
              correlation_ok, correlation_result)
    actual["local_metadata_correlation"] = correlation_result

    comparator_matched = correlate_owned_pod_events(comparator["pod"], observed_events)
    primary_matched = correlate_owned_pod_events(pod_signal, observed_events)
    foreign_events = [event for event in primary_matched if event in comparator["events"]]
    independent_result = {
        "rule": "two_owned_pod_event_uid_correlation",
        "primary_pod_uid": pod_signal["uid"],
        "primary_workload_log_fixture_id": actual["workload_log"]["fixture_id"],
        "primary_events_correlated": primary_matched == actual["events"],
        "comparator_pod_uid": comparator["pod"]["uid"],
        "comparator_workload_log_fixture_id": comparator["workload_log"]["fixture_id"],
        "comparator_events_correlated_to_comparator_only": comparator_matched == comparator["events"],
        "comparator_events_excluded_from_primary": not foreign_events,
        "uids_distinct": pod_signal["uid"] != comparator["pod"]["uid"],
    }
    independent_ok = (independent_result["primary_events_correlated"]
                      and independent_result["comparator_events_correlated_to_comparator_only"]
                      and independent_result["comparator_events_excluded_from_primary"]
                      and independent_result["uids_distinct"])
    normalized = {key: value for key, value in independent_result.items()
                  if key not in {"primary_pod_uid", "comparator_pod_uid"}}
    lab.check("correlation", "A second independently created owned Pod produces real near-miss Events that do not join to the primary workload UID",
              independent_ok, normalized)
    actual["independent_source_correlation"] = independent_result
    actual["independent_comparator"] = comparator

    evidence = {
        "control_id": CONTROL_ID, "scope": SCOPE,
        "fixture_id": fixture["fixture_id"], "fixture_window": fixture["time_window"],
        "synthetic_rule_outcomes": outcomes, "native_kubernetes_observations": actual,
        "secrets_included": False, "external_targets_contacted": False,
        "siem_connected": False, "live_attack_coverage": False,
        "gpu_metrics_observed": False, "inferenceservice_crd_installed": False,
    }
    (lab.evidence / "detection-validation.raw.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
