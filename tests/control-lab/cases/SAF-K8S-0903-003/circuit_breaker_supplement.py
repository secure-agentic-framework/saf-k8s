"""Run and collect a bounded reference breaker as an owned Kubernetes Job."""
import hashlib
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
JOB_NAME = "inference-breaker-reference"
CONFIG_NAME = JOB_NAME + "-source"
IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
         "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
SOURCE = HERE / "circuit_breaker_job.py"


def _get(lab, *args):
    return json.loads(lab.kubectl("get", *args, "-o", "json", timeout=15).stdout)


def _job_resource():
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": JOB_NAME,
                     "labels": {"saf-lab.example/fixture": "circuit-breaker-reference"}},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 35,
            "template": {
                "metadata": {"labels": {"saf-lab.example/fixture": "circuit-breaker-reference"}},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                        "runAsGroup": 65534,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "source", "configMap": {
                        "name": CONFIG_NAME, "items": [{"key": SOURCE.name,
                                                          "path": SOURCE.name}],
                        "defaultMode": 0o444}}],
                    "containers": [{
                        "name": "breaker", "image": IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "-B", "/fixture/" + SOURCE.name],
                        "volumeMounts": [{"name": "source", "mountPath": "/fixture",
                                          "readOnly": True}],
                        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                      "limits": {"cpu": "100m", "memory": "64Mi"}},
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                            "runAsGroup": 65534,
                                            "allowPrivilegeEscalation": False,
                                            "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                    }],
                },
            },
        },
    }


def _collect_job(lab):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        state = _get(lab, "job", JOB_NAME)
        settled = [condition for condition in state.get("status", {}).get("conditions", [])
                   if condition.get("status") == "True"
                   and condition.get("type") in {"Complete", "Failed"}]
        if settled:
            break
        time.sleep(0.5)
    else:
        lab.block("Owned circuit-breaker Job did not reach a bounded terminal condition")

    jobstatus = state.get("status", {})
    pods = _get(lab, "pods", "-l", "job-name=" + JOB_NAME).get("items", [])
    if len(pods) != 1:
        lab.block("Circuit-breaker Job must own exactly one Pod")
    pod = pods[0]
    owner = next((ref for ref in pod.get("metadata", {}).get("ownerReferences", [])
                  if ref.get("controller") is True and ref.get("kind") == "Job"), None)
    job_uid = state.get("metadata", {}).get("uid")
    owner_ok = bool(owner and owner.get("name") == JOB_NAME and owner.get("uid") == job_uid)
    if not owner_ok:
        lab.block("Circuit-breaker Pod is not bound to the exact observed Job UID")
    statuses = pod.get("status", {}).get("containerStatuses", [])
    if len(statuses) != 1 or statuses[0].get("name") != "breaker":
        lab.block("Circuit-breaker Pod did not report the one expected container")
    terminated = statuses[0].get("state", {}).get("terminated", {})
    podspec = pod.get("spec", {})
    container = podspec.get("containers", [{}])[0]
    pod_security = podspec.get("securityContext", {})
    container_security = container.get("securityContext", {})
    safe_spec = (
        podspec.get("restartPolicy") == "Never"
        and podspec.get("automountServiceAccountToken") is False
        and pod_security.get("runAsNonRoot") is True
        and pod_security.get("runAsUser") == 65534
        and pod_security.get("runAsGroup") == 65534
        and pod_security.get("seccompProfile", {}).get("type") == "RuntimeDefault"
        and container.get("image") == IMAGE
        and container.get("imagePullPolicy") == "IfNotPresent"
        and container.get("command") == ["python", "-B", "/fixture/" + SOURCE.name]
        and container.get("resources") == {
            "requests": {"cpu": "10m", "memory": "24Mi"},
            "limits": {"cpu": "100m", "memory": "64Mi"}}
        and container_security.get("allowPrivilegeEscalation") is False
        and container_security.get("readOnlyRootFilesystem") is True
        and container_security.get("capabilities", {}).get("drop") == ["ALL"]
        and container.get("volumeMounts") == [{"name": "source", "mountPath": "/fixture",
                                                 "readOnly": True}]
        and podspec.get("volumes") == [{"name": "source", "configMap": {
            "name": CONFIG_NAME, "items": [{"key": SOURCE.name, "path": SOURCE.name}],
            "defaultMode": 0o444}}]
    )
    if not safe_spec:
        lab.block("Circuit-breaker Job Pod differs from the pinned bounded non-root fixture contract")
    logs = lab.kubectl("logs", "pod/" + pod["metadata"]["name"], timeout=15).stdout
    if terminated.get("exitCode") != 0 or not logs.strip():
        lab.block("Circuit-breaker Job did not exit successfully with an owned observation")
    try:
        observation = json.loads(logs)
    except json.JSONDecodeError as error:
        lab.block("Circuit-breaker Job output was not one JSON observation: " + str(error))
    return {
        "job_uid": job_uid,
        "pod_uid": pod.get("metadata", {}).get("uid"),
        "pod_owner_matches_job_uid": owner_ok,
        "terminal_condition": settled[0].get("type"),
        "job_succeeded": jobstatus.get("succeeded") == 1,
        "job_failed": jobstatus.get("failed", 0),
        "container_exit_code": terminated.get("exitCode"),
        "container_id_present": bool(statuses[0].get("containerID")),
        "container_image_id_present": bool(statuses[0].get("imageID")),
        "backoff_limit": state.get("spec", {}).get("backoffLimit"),
        "active_deadline_seconds": state.get("spec", {}).get("activeDeadlineSeconds"),
        "pod_security_contract": safe_spec,
        "observation": observation,
    }


def run(lab):
    source = SOURCE.read_text(encoding="utf-8")
    source_sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
    config = lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": CONFIG_NAME}, "immutable": True,
        "data": {SOURCE.name: source},
    })
    retained_source = config.get("data", {}).get(SOURCE.name, "")
    if (config.get("immutable") is not True
            or retained_source != source
            or hashlib.sha256(retained_source.encode("utf-8")).hexdigest() != source_sha):
        lab.block("Immutable breaker source ConfigMap did not preserve the exact pinned Job program")
    lab.create(_job_resource())
    collected = _collect_job(lab)
    observations = collected["observation"].get("observations", {})
    expected_statuses = [503, 503, 200, 200]
    transition_ok = (
        collected.get("terminal_condition") == "Complete"
        and collected.get("job_succeeded") is True
        and collected.get("job_failed", 0) == 0
        and collected.get("container_exit_code") == 0
        and collected.get("container_id_present") is True
        and collected.get("container_image_id_present") is True
        and collected.get("backoff_limit") == 0
        and collected.get("active_deadline_seconds") == 35
        and collected.get("pod_security_contract") is True
        and collected.get("pod_owner_matches_job_uid") is True
        and collected.get("observation", {}).get("source_sha256") == source_sha
        and collected.get("observation", {}).get("backend_sequence") == expected_statuses
        and collected.get("observation", {}).get("backend_calls") == 4
        and collected.get("observation", {}).get("probe_errors") == []
        and collected.get("observation", {}).get("probe_thread_stopped") is True
        and observations.get("first_failure", {}).get("status") == 503
        and observations.get("first_failure", {}).get("reason") == "backend_failure"
        and observations.get("first_failure", {}).get("state") == "closed"
        and observations.get("first_failure", {}).get("backend_calls") == 1
        and observations.get("threshold_failure", {}).get("status") == 503
        and observations.get("threshold_failure", {}).get("state") == "open"
        and observations.get("threshold_failure", {}).get("backend_calls") == 2
        and observations.get("open_rejection", {}).get("status") == 503
        and observations.get("open_rejection", {}).get("reason") == "breaker_open"
        and observations.get("open_rejection", {}).get("backend_called") is False
        and observations.get("open_rejection", {}).get("backend_calls") == 2
        and observations.get("half_open_in_flight") == {
            "probe_started": True, "backend_calls": 3,
            "backend_statuses": [503, 503, 200], "half_open_probe_count": 1}
        and observations.get("competing_half_open_request", {}).get("status") == 503
        and observations.get("competing_half_open_request", {}).get("reason") == "half_open_probe_in_progress"
        and observations.get("competing_half_open_request", {}).get("backend_called") is False
        and observations.get("competing_half_open_request", {}).get("backend_calls") == 3
        and observations.get("half_open_probe", {}).get("status") == 200
        and observations.get("half_open_probe", {}).get("state") == "closed"
        and observations.get("half_open_probe", {}).get("backend_calls") == 3
        and observations.get("half_open_probe", {}).get("half_open_probe_count") == 1
        and observations.get("recovered_request", {}).get("status") == 200
        and observations.get("recovered_request", {}).get("state") == "closed"
        and observations.get("recovered_request", {}).get("backend_calls") == 4
    )
    (lab.evidence / "circuit-breaker-reference.raw.json").write_text(
        json.dumps({"scope": "case-owned non-root Kubernetes Job; loopback-only stdlib backend and reference breaker",
                    "source_sha256": source_sha,
                    "job": {key: value for key, value in collected.items() if key != "observation"},
                    "observation": collected.get("observation")},
                   indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lab.check("positive", "A case-owned non-root Job runs the bounded breaker, short-circuits an open request, admits one half-open probe, and recovers",
              transition_ok,
              {"job_completed_under_expected_owner_and_security_contract":
                   collected.get("terminal_condition") == "Complete"
                   and collected.get("job_succeeded") is True
                   and collected.get("container_exit_code") == 0
                   and collected.get("backoff_limit") == 0
                   and collected.get("active_deadline_seconds") == 35
                   and collected.get("pod_owner_matches_job_uid") is True
                   and collected.get("pod_security_contract") is True,
               "fixed_backend_statuses": collected.get("observation", {}).get("backend_sequence"),
               "open_rejection_did_not_call_backend": observations.get("open_rejection", {}).get("backend_calls") == 2,
               "only_one_half_open_probe_reached_backend":
                   observations.get("half_open_in_flight", {}).get("backend_calls") == 3
                   and observations.get("competing_half_open_request", {}).get("backend_calls") == 3
                   and observations.get("half_open_probe", {}).get("half_open_probe_count") == 1,
               "healthy_probe_closed_and_next_request_reached_backend":
                   observations.get("half_open_probe", {}).get("state") == "closed"
                   and observations.get("recovered_request", {}).get("backend_calls") == 4})
