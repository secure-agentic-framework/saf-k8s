"""Exercise native kube-apiserver file rotation with two bounded fixture writes."""
import hashlib
import json
import re

NAMESPACE = "saf-test"
AUDIT_DIR = "/var/log/kubernetes/audit"
AUDIT_FILE = f"{AUDIT_DIR}/audit.jsonl"
MAXSIZE_MIB = 1
MAXSIZE_BYTES = MAXSIZE_MIB * 1024 * 1024
MAXBACKUP = 2
ACTIVE_NAME = "audit.jsonl"
ROTATED_NAME = re.compile(r"^audit-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}\.jsonl$")
MAXAGE_DAYS = 7
VALUE_BYTES = 400 * 1024
MARKERS = ("saf-audit-rotation-a", "saf-audit-rotation-b")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def policy_text():
    return (
        "apiVersion: audit.k8s.io/v1\nkind: Policy\nomitStages: [RequestReceived]\nrules:\n"
        "  - level: RequestResponse\n"
        "    verbs: [create]\n"
        f"    namespaces: [{NAMESPACE}]\n"
        "    resources:\n      - group: \"\"\n        resources: [configmaps]\n"
        "  - level: None\n"
    )


def kind_config(policy, audit_dir):
    return (
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n"
        "  - role: control-plane\n    extraMounts:\n"
        f"      - hostPath: {json.dumps(str(policy))}\n"
        "        containerPath: /etc/kubernetes/audit-policy.yaml\n        readOnly: true\n"
        f"      - hostPath: {json.dumps(str(audit_dir))}\n"
        f"        containerPath: {AUDIT_DIR}\n        readOnly: false\n"
        "kubeadmConfigPatches:\n  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n    kind: ClusterConfiguration\n"
        "    apiServer:\n      extraArgs:\n"
        "        - name: audit-policy-file\n          value: /etc/kubernetes/audit-policy.yaml\n"
        f"        - name: audit-log-path\n          value: {AUDIT_FILE}\n"
        "        - name: audit-log-format\n          value: json\n"
        "        - name: audit-log-mode\n          value: blocking\n"
        f"        - name: audit-log-maxsize\n          value: \"{MAXSIZE_MIB}\"\n"
        f"        - name: audit-log-maxbackup\n          value: \"{MAXBACKUP}\"\n"
        f"        - name: audit-log-maxage\n          value: \"{MAXAGE_DAYS}\"\n"
        "        - name: audit-log-compress\n          value: \"false\"\n"
        "      extraVolumes:\n"
        "        - name: audit-policy\n"
        "          hostPath: /etc/kubernetes/audit-policy.yaml\n"
        "          mountPath: /etc/kubernetes/audit-policy.yaml\n"
        "          readOnly: true\n          pathType: File\n"
        "        - name: audit-log\n"
        f"          hostPath: {AUDIT_DIR}\n          mountPath: {AUDIT_DIR}\n"
        "          readOnly: false\n          pathType: DirectoryOrCreate\n"
    )


def prepare_kind(lab, temporary):
    audit_dir = temporary / "rotation-audit"
    audit_dir.mkdir()
    policy = temporary / "audit-policy-rotation.yaml"
    policy.write_text(policy_text())
    config = temporary / "kind-audit-rotation.yaml"
    config.write_text(kind_config(policy, audit_dir))
    return config


def kubectl(lab, *args, timeout=45):
    return lab.kubectl(*args, timeout=timeout)


def event_for_marker(event, marker):
    return (event.get("objectRef", {}).get("resource") == "configmaps"
            and event.get("objectRef", {}).get("namespace") == NAMESPACE
            and event.get("objectRef", {}).get("name") == marker
            and event.get("verb") == "create")


def run(lab, temporary):
    version = json.loads(kubectl(lab, "version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    if version != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1 for rotation fixture, got {version}")
    audit_dir = temporary / "rotation-audit"
    audit_path = audit_dir / "audit.jsonl"
    policy_path = temporary / "audit-policy-rotation.yaml"
    config_path = temporary / "kind-audit-rotation.yaml"
    lab.kubectl("create", "namespace", NAMESPACE)
    baseline_size = audit_path.stat().st_size if audit_path.exists() else 0
    baseline_hash = sha256(audit_path.read_bytes()) if audit_path.exists() else None

    for marker in MARKERS:
        manifest = temporary / f"{marker}.json"
        obj = {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": marker, "namespace": NAMESPACE},
            "data": {"fixture": "x" * VALUE_BYTES, "marker": marker},
        }
        manifest.write_text(json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n")
        kubectl(lab, "create", "-f", str(manifest), timeout=45)

    # Kube-apiserver backup names are version/backend owned; discover the active
    # path plus any siblings with the audit basename instead of assuming suffix form.
    paths = sorted((path for path in audit_dir.iterdir() if path.is_file()),
                   key=lambda path: path.name)
    rotated = [path for path in paths if ROTATED_NAME.fullmatch(path.name)]
    filenames_valid = (audit_path.is_file() and len(rotated) == 1
                       and all(path.name == ACTIVE_NAME or ROTATED_NAME.fullmatch(path.name)
                               for path in paths))
    records = []
    for path in paths:
        for line in path.read_bytes().splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            for marker in MARKERS:
                if event_for_marker(event, marker):
                    request_obj = event.get("requestObject", {})
                    response_obj = event.get("responseObject", {})
                    request_value = request_obj.get("data", {}).get("fixture", "")
                    response_value = response_obj.get("data", {}).get("fixture", "")
                    records.append({
                        "marker": marker,
                        "audit_id": event.get("auditID"),
                        "file": path.name,
                        "line_bytes": len(line) + 1,
                        "line_sha256": sha256(line),
                        "stage": event.get("stage"),
                        "level": event.get("level"),
                        "response_code": event.get("responseStatus", {}).get("code"),
                        "request_value_bytes": len(request_value.encode("utf-8")) if isinstance(request_value, str) else -1,
                        "response_value_bytes": len(response_value.encode("utf-8")) if isinstance(response_value, str) else -1,
                        "full_request_response_present": (request_value == "x" * VALUE_BYTES
                                                           and response_value == "x" * VALUE_BYTES),
                    })

    file_observations = [
        {"name": path.name, "bytes": path.stat().st_size, "sha256": sha256(path.read_bytes())}
        for path in paths
    ]
    occurrences = {marker: sum(item["marker"] == marker for item in records) for marker in MARKERS}
    records.sort(key=lambda item: MARKERS.index(item["marker"]))
    event_ids = [item["audit_id"] for item in records]
    line_bytes = [item["line_bytes"] for item in records]
    aggregate_bytes = sum(item["bytes"] for item in file_observations)
    rotation_observed = filenames_valid
    exact_once = all(occurrences[marker] == 1 for marker in MARKERS)
    unique_ids = len(event_ids) == 2 and None not in event_ids and len(set(event_ids)) == 2
    exact_events = (len(records) == 2 and all(
        item["stage"] == "ResponseComplete" and item["level"] == "RequestResponse"
        and item["response_code"] == 201 and item["full_request_response_present"]
        for item in records))
    each_event_below_threshold = len(line_bytes) == 2 and all(size < MAXSIZE_BYTES for size in line_bytes)
    first_event_rotated = (len(records) == 2 and records[0]["file"] in {path.name for path in rotated})
    second_event_active = (len(records) == 2 and records[1]["file"] == ACTIVE_NAME)
    pair_crosses_threshold = (len(line_bytes) == 2 and all(size < MAXSIZE_BYTES for size in line_bytes)
                              and baseline_size + line_bytes[0] < MAXSIZE_BYTES
                              and baseline_size + sum(line_bytes) > MAXSIZE_BYTES
                              and first_event_rotated and second_event_active)
    bounded = aggregate_bytes <= 4 * MAXSIZE_BYTES and len(paths) <= MAXBACKUP + 1
    result = {
        "fixture_only": True,
        "configured_maxsize_mib": MAXSIZE_MIB,
        "configured_maxbackup": MAXBACKUP,
        "configured_maxage_days": MAXAGE_DAYS,
        "configuration_sha256": sha256(config_path.read_bytes()),
        "policy_sha256": sha256(policy_path.read_bytes()),
        "value_bytes_per_configmap": VALUE_BYTES,
        "baseline_file_bytes": baseline_size,
        "baseline_file_sha256": baseline_hash,
        "rotation_observed": rotation_observed,
        "active_filename": ACTIVE_NAME,
        "rotated_filenames": [path.name for path in rotated],
        "filenames_valid": filenames_valid,
        "first_marker_in_rotated_file": first_event_rotated,
        "second_marker_in_active_file": second_event_active,
        "rotated_file_count": len(rotated),
        "exact_once": exact_once,
        "distinct_audit_ids": unique_ids,
        "exact_high_fidelity_events": exact_events,
        "each_event_below_threshold": each_event_below_threshold,
        "pair_crosses_threshold": pair_crosses_threshold,
        "bounded_files": bounded,
        "aggregate_file_bytes": aggregate_bytes,
        "occurrences": occurrences,
        "files": file_observations,
        "events": records,
    }
    (lab.evidence / "audit-rotation-observation.raw.json").write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n")
    return {
        "rotation_observed": rotation_observed,
        "native_file_names_match": filenames_valid,
        "first_marker_rotated_second_active": first_event_rotated and second_event_active,
        "two_distinct_events_retained_once": exact_once and unique_ids,
        "request_response_fidelity_preserved": exact_events,
        "two_subthreshold_records_cross_limit": each_event_below_threshold and pair_crosses_threshold,
        "output_bounded": bounded,
    }
