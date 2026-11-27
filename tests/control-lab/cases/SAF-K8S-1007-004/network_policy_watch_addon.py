"""Exercise one exact owned NetworkPolicy watch without connectivity probes."""
import datetime
import json
from pathlib import Path
import time

IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
OBSERVER = "saf-network-policy-watch"
EXCLUDED = "saf-network-policy-watch-unselected"


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds")


def parse_time(value):
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def run(lab, case_dir, namespace, name, baseline, neighbor_namespace):
    policy = json.loads(lab.kubectl("-n", namespace, "get", "networkpolicy", name, "-o", "json").stdout)
    uid = policy["metadata"]["uid"]
    if policy["spec"] != baseline or not uid:
        lab.block("The NetworkPolicy watcher did not start from the exact restored fixture policy")

    api = "rbac.authorization.k8s.io/v1"
    lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps({
        "apiVersion": "v1", "kind": "ServiceAccount",
        "metadata": {"name": OBSERVER, "namespace": namespace},
        "automountServiceAccountToken": False,
    }))
    lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps({
        "apiVersion": api, "kind": "Role", "metadata": {"name": OBSERVER, "namespace": namespace},
        "rules": [
            {"apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies"],
             "resourceNames": [name], "verbs": ["list", "watch"]},
            {"apiGroups": ["events.k8s.io"], "resources": ["events"], "verbs": ["create"]},
        ],
    }))
    lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps({
        "apiVersion": api, "kind": "RoleBinding", "metadata": {"name": OBSERVER, "namespace": namespace},
        "subjects": [{"kind": "ServiceAccount", "name": OBSERVER, "namespace": namespace}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": OBSERVER},
    }))
    lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps({
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": OBSERVER, "namespace": namespace},
        "immutable": True, "data": {"client.py": (Path(case_dir) / "network_policy_watch_client.py").read_text()},
    }))
    env = {"WATCH_NAMESPACE": namespace, "WATCH_POLICY": name, "WATCH_UID": uid,
           "EXCLUDED_POLICY": EXCLUDED, "EXCLUDED_NAMESPACE": neighbor_namespace,
           "EXPECTED_SPEC": json.dumps(baseline)}
    job = json.loads(lab.kubectl("-n", namespace, "create", "-f", "-", "-o", "json", payload=json.dumps({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": OBSERVER, "namespace": namespace},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 120,
                 "template": {"spec": {
                     "restartPolicy": "Never", "serviceAccountName": OBSERVER,
                     "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{
                         "name": "watch", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                         "command": ["python", "-B", "/fixture/client.py"],
                         "env": ([{"name": key, "value": value} for key, value in env.items()]
                                 + [{"name": "WATCH_POD_UID", "valueFrom": {
                                     "fieldRef": {"fieldPath": "metadata.uid"}}}]),
                         "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                       "limits": {"cpu": "100m", "memory": "64Mi"}},
                         "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                             "capabilities": {"drop": ["ALL"]}},
                         "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                                          {"name": "gate", "mountPath": "/gate"},
                                          {"name": "identity", "mountPath": "/var/run/saf-watch", "readOnly": True}],
                     }],
                     "volumes": [
                         {"name": "gate", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}},
                         {"name": "fixture", "configMap": {"name": OBSERVER}},
                         {"name": "identity", "projected": {"sources": [
                             {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
                             {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
                         ]}},
                     ],
                 }},
             },
    })).stdout)

    def records():
        output = lab.kubectl("-n", namespace, "logs", f"job/{OBSERVER}", "--limit-bytes=32768",
                             timeout=12, allow_failure=True)
        return [json.loads(line) for line in output.stdout.splitlines() if line.startswith("{")]

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        current = records()
        if current and current[0].get("phase") == "armed":
            break
        time.sleep(0.5)
    else:
        lab.block("The authenticated NetworkPolicy stream did not open")
    armed = current[0]

    def patch(body):
        started = utc_now()
        output = lab.kubectl("-n", namespace, "patch", "networkpolicy", name, "--type=merge",
                             "--field-manager=saf-1007-004-network-policy-watch", "-p", json.dumps(body), "-o", "json")
        completed = utc_now()
        observed = json.loads(output.stdout)
        return {"request_started_at_utc": started, "response_received_at_utc": completed,
                "uid": observed["metadata"]["uid"], "resource_version": observed["metadata"]["resourceVersion"],
                "generation": observed["metadata"].get("generation"), "spec": observed["spec"],
                "managed_fields": [{k: row.get(k) for k in ("manager", "operation", "time")}
                                    for row in observed["metadata"].get("managedFields", [])]}

    metadata = patch({"metadata": {"labels": {"saf-k8s.example/watch-observation": "metadata-only"}}})
    widened_spec = {**baseline, "ingress": [{}]}
    drifted = patch({"spec": widened_spec})
    restored = patch({"spec": {**baseline, "ingress": None}})

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        current = records()
        if [record.get("phase") for record in current] == ["armed", "complete"]:
            break
        time.sleep(0.25)
    else:
        lab.block("The initial NetworkPolicy watch did not complete and close")
    gap_drift = patch({"spec": widened_spec})
    gap_restore = patch({"spec": {**baseline, "ingress": None}})
    live = json.loads(lab.kubectl("-n", namespace, "get", "networkpolicy", name, "-o", "json").stdout)
    pre_resume = {"uid": live["metadata"]["uid"], "resource_version": live["metadata"]["resourceVersion"],
                  "spec": live["spec"], "read_at_utc": utc_now()}
    pods = json.loads(lab.kubectl("-n", namespace, "get", "pods", "-l",
                                  "batch.kubernetes.io/job-name=" + OBSERVER, "-o", "json").stdout)
    pod, = pods["items"]
    job_uid = job["metadata"]["uid"]
    pod_identity = (pod["spec"].get("serviceAccountName") == OBSERVER
                    and pod["spec"].get("automountServiceAccountToken") is False
                    and any(owner.get("kind") == "Job" and owner.get("uid") == job_uid
                            and owner.get("controller") is True for owner in pod["metadata"].get("ownerReferences", [])))
    gate_released = utc_now()
    lab.kubectl("-n", namespace, "exec", pod["metadata"]["name"], "-c", "watch", "--",
                "python", "-B", "-c", "from pathlib import Path; Path('/gate/resume').touch(exist_ok=False)")
    lab.kubectl("-n", namespace, "wait", "--for=condition=Complete", f"job/{OBSERVER}", "--timeout=30s", timeout=35)
    armed, complete, resumed, recovery = records()

    events = complete["events"]
    writes = [metadata, drifted, restored]
    expected_decisions = ["unchanged", "drift", "recovered"]
    expected_specs = [baseline, widened_spec, baseline]
    trace_matches = complete.get("phase") == "complete" and len(events) == 3
    timestamps_match = len(events) == 3
    for event, write, decision, spec in zip(events, writes, expected_decisions, expected_specs):
        try:
            event_time = parse_time(event["event_received_at_utc"])
            request_started = parse_time(write["request_started_at_utc"])
            response_received = parse_time(write["response_received_at_utc"])
            times_valid = (event_time >= request_started
                           and event_time <= response_received + datetime.timedelta(seconds=5))
        except (KeyError, TypeError, ValueError):
            times_valid = False
        timestamps_match = timestamps_match and times_valid
        trace_matches = trace_matches and (event.get("uid") == uid
                                            and event.get("resource_version") == write["resource_version"]
                                            and event.get("generation") == write["generation"]
                                            and event.get("decision") == decision
                                            and event.get("spec") == spec)
    unique_versions = (len({write["resource_version"] for write in writes}) == 3
                       and len({event.get("resource_version") for event in events}) == 3)
    independent_writes = (len(writes) == 3 and all(
        parse_time(writes[index + 1]["request_started_at_utc"])
        >= parse_time(writes[index]["response_received_at_utc"])
        for index in range(2)))
    ordered_times = all(parse_time(events[i]["event_received_at_utc"]) < parse_time(events[i+1]["event_received_at_utc"])
                        for i in range(2)) if len(events) == 3 else False
    denied = armed.get("unfiltered_status") == armed.get("excluded_status") == 403
    opened = (armed.get("http_status") == 200 and armed.get("baseline_uid") == uid
              and armed.get("baseline_spec") == baseline and bool(armed.get("list_resource_version")))
    exact_scope = (pod_identity and all(write["uid"] == uid for write in writes))

    (lab.evidence / "posture-network-policy-watch.raw.json").write_text(json.dumps({
        "fixture_only": True, "watch": armed, "events": events, "api_writes": writes,
        "job_uid": job_uid, "pod_uid": pod["metadata"]["uid"], "pod_owner_and_service_account_bound": pod_identity,
        "scope": {"namespace": namespace, "policy_name": name, "policy_uid": uid,
                  "no_connectivity_probes": True, "no_external_target": True},
    }, indent=2, sort_keys=True) + "\n")
    lab.check("positive", "Named NetworkPolicy list and watch succeed while broader and different-name watches receive 403",
              opened and denied and exact_scope,
              {"scoped_stream_open": opened, "unfiltered_watch_403": armed.get("unfiltered_status") == 403,
               "different_name_watch_403": armed.get("excluded_status") == 403,
               "job_pod_identity_bound": pod_identity, "exact_policy_uid_preserved": all(w["uid"] == uid for w in writes)})
    lab.check("green", "NetworkPolicy watch classifies metadata, ingress widening and restoration against exact writes and event times",
              trace_matches and unique_versions and independent_writes and timestamps_match and ordered_times,
              {"ordered_event_trace_matches_api_writes": trace_matches, "resource_versions_unique": unique_versions,
               "writes_are_separate_sequential_api_responses": independent_writes,
               "event_receipt_times_bounded_to_independent_writes": timestamps_match,
               "event_receipt_times_ordered": ordered_times,
               "comparison": ["unchanged", "drift", "recovered"]})

    gap_writes = [gap_drift, gap_restore]
    gap_events = recovery["events"]
    gap_spec_matches = (pre_resume["uid"] == uid and pre_resume["spec"] == baseline
                        and pre_resume["resource_version"] == gap_restore["resource_version"])
    checkpoint_matches = (resumed["phase"] == "resumed" and resumed["http_status"] == 200
                          and resumed["resource_version"] == complete["checkpoint"]
                          == restored["resource_version"])
    gap_trace_matches = (recovery["phase"] == "recovery_complete" and len(gap_events) == 2
                         and len({w["resource_version"] for w in [*writes, *gap_writes]}) == 5
                         and [event["decision"] for event in gap_events] == ["drift", "recovered"]
                         and [event["spec"] for event in gap_events] == [widened_spec, baseline]
                         and all(event["uid"] == write["uid"] == uid
                                 and event["resource_version"] == write["resource_version"]
                                 and event["generation"] == write["generation"]
                                 and event["spec"] == write["spec"]
                                 for event, write in zip(gap_events, gap_writes)))
    gap_boundaries = (parse_time(complete["complete_at"]) <= parse_time(gap_drift["request_started_at_utc"])
                      <= parse_time(gap_drift["response_received_at_utc"])
                      <= parse_time(gap_restore["request_started_at_utc"])
                      <= parse_time(gap_restore["response_received_at_utc"])
                      <= parse_time(pre_resume["read_at_utc"]) <= parse_time(gate_released)
                      <= parse_time(resumed["resumed_at"])
                      and all(parse_time(event["event_received_at_utc"]) >= parse_time(resumed["resumed_at"])
                              for event in gap_events))
    (lab.evidence / "posture-network-policy-watch-resume.raw.json").write_text(json.dumps({
        "fixture_only": True, "closed_at": complete["complete_at"],
        "checkpoint": complete["checkpoint"], "checkpoint_write": restored,
        "gap_writes": gap_writes, "get_before_resume": pre_resume, "gate_released_at": gate_released,
        "resumed": resumed, "resumed_events": gap_events, "job_uid": job_uid,
        "pod_uid": pod["metadata"]["uid"], "pod_owner_and_service_account_bound": pod_identity,
    }, indent=2, sort_keys=True) + "\n")
    lab.check("green", "NetworkPolicy watch resumes from the last received revision and observes drift missed while disconnected",
              pod_identity and gap_spec_matches and checkpoint_matches and gap_trace_matches and gap_boundaries,
              {"exact_checkpoint_used": checkpoint_matches, "writes_while_stream_closed": gap_boundaries,
               "independent_read_shows_restored_spec": gap_spec_matches,
               "resumed_events_match_exact_missed_writes": gap_trace_matches,
               "job_pod_identity_bound": pod_identity})

    # The watcher emits an API-side Warning Event only for actual drift transitions.
    alert_responses = [event.get("alert_sink_response") for event in [*events, *gap_events]
                       if event.get("decision") == "drift"]
    alert_list = json.loads(lab.kubectl(
        "-n", namespace, "get", "events.events.k8s.io", "-o", "json").stdout)
    persisted = [event for event in alert_list.get("items", [])
                 if event.get("reportingController") == "saf-k8s.example/network-policy-posture-watch"]
    probe_status = armed.get("neighbor_event_create_status")
    probe_name = armed.get("neighbor_event_probe_name")
    probe_absence = lab.kubectl(
        "-n", neighbor_namespace, "get", "events.events.k8s.io", probe_name,
        "-o", "name", "--ignore-not-found", allow_failure=True)
    probe_not_created = probe_absence.returncode == 0 and not probe_absence.stdout.strip()

    expected_drift_writes = [drifted, gap_drift]
    expected_source_versions = [write["resource_version"] for write in expected_drift_writes]
    by_source = {event.get("metadata", {}).get("annotations", {}).get(
        "saf-k8s.example/source-resource-version"): event for event in persisted}
    source_versions_match = (len(persisted) == 2 and len(by_source) == 2
                             and set(by_source) == set(expected_source_versions))
    no_non_drift_alerts = all(
        event.get("alert_sink_response") is None
        for event in [*events, *gap_events] if event.get("decision") != "drift")
    owner_and_subject_match = source_versions_match and pod_identity
    event_payloads_safe = source_versions_match
    api_responses_match = source_versions_match and len(alert_responses) == 2
    for write, response in zip(expected_drift_writes, alert_responses):
        event = by_source.get(write["resource_version"], {})
        metadata = event.get("metadata", {})
        regarding = event.get("regarding", {})
        owner_and_subject_match = owner_and_subject_match and (
            metadata.get("namespace") == namespace
            and metadata.get("labels", {}).get("saf-k8s.example/control-1007-004")
            == "network-policy-alert"
            and event.get("reportingController") == "saf-k8s.example/network-policy-posture-watch"
            and event.get("reportingInstance") == pod["metadata"]["uid"]
            and regarding == {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                              "namespace": namespace, "name": name, "uid": uid}
            and metadata.get("annotations", {}).get("saf-k8s.example/source-resource-version")
            == write["resource_version"])
        event_payloads_safe = event_payloads_safe and (
            event.get("type") == "Warning" and event.get("reason") == "NetworkPolicyPostureDrift"
            and event.get("action") == "DetectPostureDrift"
            and event.get("note") == "Fixture-owned NetworkPolicy posture differs from its declared baseline."
            and bool(event.get("eventTime")))
        api_responses_match = api_responses_match and (
            response is not None and response.get("status") == 201
            and response.get("event_name") == metadata.get("name")
            and response.get("event_uid") == metadata.get("uid")
            and response.get("event_resource_version") == metadata.get("resourceVersion")
            and response.get("source_resource_version") == write["resource_version"])
    persisted_raw = [{
        "name": e.get("metadata", {}).get("name"),
        "uid": e.get("metadata", {}).get("uid"),
        "resource_version": e.get("metadata", {}).get("resourceVersion"),
        "annotations": e.get("metadata", {}).get("annotations", {}),
        "reportingController": e.get("reportingController"),
        "reportingInstance": e.get("reportingInstance"),
        "regarding": e.get("regarding"), "eventTime": e.get("eventTime"),
        "type": e.get("type"), "reason": e.get("reason"), "action": e.get("action"),
        "note": e.get("note"),
    } for e in persisted]
    (lab.evidence / "posture-network-policy-alert-events.raw.json").write_text(json.dumps({
        "fixture_only": True, "namespace": namespace, "policy_name": name, "policy_uid": uid,
        "job_uid": job_uid, "pod_uid": pod["metadata"]["uid"],
        "pod_owner_and_service_account_bound": pod_identity,
        "neighbor_event_create_status": probe_status, "neighbor_probe_event_absent": probe_not_created,
        "expected_drift_source_resource_versions": expected_source_versions,
        "watcher_api_create_responses": alert_responses, "persisted_events": persisted_raw,
    }, indent=2, sort_keys=True) + "\n")
    lab.check("positive", "The watcher emits exactly one persisted Warning Event for each observed NetworkPolicy drift revision",
              source_versions_match and owner_and_subject_match and event_payloads_safe
              and api_responses_match and no_non_drift_alerts,
              {"persisted_event_count": len(persisted), "expected_drift_count": 2,
               "source_resource_versions_match": source_versions_match,
               "source_policy_and_reporter_identity_bound": owner_and_subject_match,
               "warning_action_reason_and_note_bounded": event_payloads_safe,
               "create_responses_match_persisted_objects": api_responses_match,
               "no_event_for_unchanged_or_recovered": no_non_drift_alerts})
    lab.check("positive", "The watcher identity cannot create or leave an alert Event in the neighboring namespace",
              probe_status == 403 and probe_not_created,
              {"neighbor_create_status_403": probe_status == 403,
               "neighbor_probe_event_absent": probe_not_created})
