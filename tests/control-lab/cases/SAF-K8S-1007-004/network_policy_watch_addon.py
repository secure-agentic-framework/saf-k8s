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


def run(lab, case_dir, namespace, name, baseline):
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
        "rules": [{"apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies"],
                   "resourceNames": [name], "verbs": ["list", "watch"]}],
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
           "EXCLUDED_POLICY": EXCLUDED, "EXPECTED_SPEC": json.dumps(baseline)}
    job = json.loads(lab.kubectl("-n", namespace, "create", "-f", "-", "-o", "json", payload=json.dumps({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": OBSERVER, "namespace": namespace},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 100,
                 "template": {"spec": {
                     "restartPolicy": "Never", "serviceAccountName": OBSERVER,
                     "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{
                         "name": "watch", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                         "command": ["python", "-B", "/fixture/client.py"],
                         "env": [{"name": key, "value": value} for key, value in env.items()],
                         "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                       "limits": {"cpu": "100m", "memory": "64Mi"}},
                         "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                             "capabilities": {"drop": ["ALL"]}},
                         "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                                          {"name": "identity", "mountPath": "/var/run/saf-watch", "readOnly": True}],
                     }],
                     "volumes": [
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
    lab.kubectl("-n", namespace, "wait", "--for=condition=Complete", f"job/{OBSERVER}", "--timeout=45s", timeout=50)
    final_records = records()
    armed, complete = final_records
    pods = json.loads(lab.kubectl("-n", namespace, "get", "pods", "-l",
                                  "batch.kubernetes.io/job-name=" + OBSERVER, "-o", "json").stdout)
    pod, = pods["items"]
    job_uid = job["metadata"]["uid"]
    pod_identity = (pod["spec"].get("serviceAccountName") == OBSERVER
                    and pod["spec"].get("automountServiceAccountToken") is False
                    and any(owner.get("kind") == "Job" and owner.get("uid") == job_uid
                            and owner.get("controller") is True for owner in pod["metadata"].get("ownerReferences", [])))

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
