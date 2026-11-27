"""Exercise the posture watcher against one real API stream and scoped edits."""
import json
from pathlib import Path
import time


IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
OBSERVER = "saf-role-watch"
EXCLUDED = "saf-role-watch-unselected"


def run(lab, case_dir, namespace, name, baseline):
    def create(api, kind, resource, **fields):
        document = {"apiVersion": api, "kind": kind, "metadata": {"name": resource},
                    **fields}
        result = lab.kubectl("-n", namespace, "create", "-f", "-", "-o", "json",
                             payload=json.dumps(document))
        return json.loads(result.stdout)

    api = "rbac.authorization.k8s.io/v1"
    role = json.loads(lab.kubectl("-n", namespace, "get", "role", name, "-o", "json").stdout)
    uid = role["metadata"]["uid"]
    if role["rules"] != baseline or not uid:
        lab.block("The role watcher did not start from the restored fixture role")
    create(api, "Role", EXCLUDED, rules=baseline)
    create("v1", "ServiceAccount", OBSERVER, automountServiceAccountToken=False)
    create(api, "Role", OBSERVER, rules=[
        {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles"],
         "resourceNames": [name], "verbs": ["list", "watch"]},
    ])
    create(api, "RoleBinding", OBSERVER,
           subjects=[{"kind": "ServiceAccount", "name": OBSERVER, "namespace": namespace}],
           roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": OBSERVER})
    create("v1", "ConfigMap", OBSERVER, immutable=True,
           data={"client.py": (Path(case_dir) / "role_watch_client.py").read_text()})
    args = {"WATCH_NAMESPACE": namespace, "WATCH_ROLE": name, "WATCH_UID": uid,
            "EXCLUDED_ROLE": EXCLUDED, "EXPECTED_RULES": json.dumps(baseline)}
    job = create("batch/v1", "Job", OBSERVER, spec={
        "backoffLimit": 0, "activeDeadlineSeconds": 100,
        "template": {"spec": {
            "restartPolicy": "Never", "serviceAccountName": OBSERVER,
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "watch", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "/fixture/client.py"],
                "env": [{"name": key, "value": value} for key, value in args.items()],
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
                "securityContext": {"readOnlyRootFilesystem": True,
                                    "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
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
    })

    def logs():
        output = lab.kubectl("-n", namespace, "logs", f"job/{OBSERVER}",
                             "--limit-bytes=32768", timeout=12, allow_failure=True)
        return [json.loads(line) for line in output.stdout.splitlines() if line.startswith("{")]

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        records = logs()
        if records and records[0]["phase"] == "armed":
            break
        time.sleep(0.5)
    else:
        lab.block("The authenticated Role stream did not open")
    armed = records[0]

    def patch(role_name, body):
        output = lab.kubectl("-n", namespace, "patch", "role", role_name, "--type=merge",
                             "-p", json.dumps(body), "-o", "json")
        return json.loads(output.stdout)

    metadata = patch(name, {"metadata": {"labels": {"saf-k8s.example/observation": "unchanged"}}})
    outside = patch(EXCLUDED, {"metadata": {"labels": {"saf-k8s.example/observation": "excluded"}}})
    widened = [{**row, "verbs": ["get", "list"]} for row in baseline]
    drifted = patch(name, {"rules": widened})
    restored = patch(name, {"rules": baseline})
    lab.kubectl("-n", namespace, "wait", "--for=condition=Complete", f"job/{OBSERVER}",
                "--timeout=45s", timeout=50)
    armed, complete = logs()
    pods = json.loads(lab.kubectl("-n", namespace, "get", "pods",
                                  "-l", "batch.kubernetes.io/job-name=" + OBSERVER, "-o", "json").stdout)
    pod, = pods["items"]
    owner_uid = job["metadata"]["uid"]
    identity = (pod["spec"]["serviceAccountName"] == OBSERVER
                and pod["spec"]["automountServiceAccountToken"] is False
                and any(owner["kind"] == "Job" and owner["uid"] == owner_uid and owner.get("controller") is True
                        for owner in pod["metadata"]["ownerReferences"]))
    expected = [{"uid": uid, "resource_version": obj["metadata"]["resourceVersion"],
                 "decision": decision, "rules": rules}
                for obj, decision, rules in ((metadata, "unchanged", baseline),
                                              (drifted, "drift", widened),
                                              (restored, "recovered", baseline))]
    events = complete["events"]
    denied = armed["unfiltered_status"] == armed["excluded_status"] == 403
    opened = (armed["http_status"] == 200 and armed["baseline_uid"] == uid
              and armed["baseline_rules"] == baseline and bool(armed["list_resource_version"]))
    matching_trace = (complete["phase"] == "complete" and events == expected
                      and len({event["resource_version"] for event in events}) == 3)
    excluded = all(outside["metadata"]["resourceVersion"] != event["resource_version"] for event in events)
    (lab.evidence / "posture-role-watch.raw.json").write_text(json.dumps({
        "watch": armed, "events": events, "owned_api_patches": [metadata, drifted, restored],
        "excluded_api_patch": outside, "job_uid": owner_uid, "pod_uid": pod["metadata"]["uid"],
        "pod_owner_and_service_account_bound": identity,
    }, indent=2, sort_keys=True) + "\n")
    lab.check("positive", "Named Role list and watch succeed while unfiltered and different-name watches receive 403",
              opened and denied and identity,
              {"scoped_stream_open": opened, "unfiltered_watch_403": armed["unfiltered_status"] == 403,
               "different_name_watch_403": armed["excluded_status"] == 403, "job_pod_identity_bound": identity})
    lab.check("green", "Live Role watch distinguishes metadata, policy widening and restored policy on one UID",
              matching_trace and excluded,
              {"ordered_watch_matches_exact_api_revisions": matching_trace,
               "excluded_role_event_absent": excluded, "comparison": ["unchanged", "drift", "recovered"]})
