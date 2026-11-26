"""Verify scheduled scoped Kubernetes evidence capture and recovery."""
from datetime import datetime, timezone
import json
from pathlib import Path
import runpy
import time

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-1006-004-evidence"
NAME = "evidence-snapshot"
IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
         "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
FRESHNESS = 12
PSA = {
    "pod-security.kubernetes.io/enforce": "restricted",
    "pod-security.kubernetes.io/enforce-version": "v1.36",
}
SCOPE = (
    "Disposable Kind cluster. A Kubernetes CronJob uses its own read-only, named-object "
    "identity to collect inert catalog and crosswalk records and live Pod Security "
    "Admission labels twice. It writes both "
    "snapshots to a PVC where a separate Pod reads them. The lab demonstrates missing, "
    "fresh, stale, and recovered states under a fixture timing threshold. The scoped follow-on checks live RoleBindings, NetworkPolicies, Namespace labels, "
    "object provenance, and cross-namespace denial. A separate source-pinned synthetic fixture "
    "checks crosswalk import and readiness-gap projection; it does not assert any actual NIST, EU, "
    "or other framework coverage. Scope remains capture and freshness for the native inputs."
)


def kubectl(lab, *args, **kwargs):
    return lab.kubectl("-n", NAMESPACE, *args, **kwargs)


def create(lab, kind, name, api="v1", **content):
    kubectl(lab, "create", "-f", "-", payload=json.dumps({
        "apiVersion": api, "kind": kind, "metadata": {"namespace": NAMESPACE, "name": name}, **content,
    }))


def get_json(lab, *args):
    return json.loads(kubectl(lab, *args, "-o", "json").stdout)


def patch(lab, kind, name, data):
    kubectl(lab, "patch", kind, name, "--type=merge", "-p", json.dumps(data))


def configure(lab, fixtures):
    create(lab, "ServiceAccount", "evidence-reader")
    rbac = "rbac.authorization.k8s.io"
    create(lab, "Role", "evidence-reader", f"{rbac}/v1", rules=[{
        "apiGroups": [""], "resources": ["configmaps"], "resourceNames": list(fixtures), "verbs": ["get"],
    }])
    create(lab, "RoleBinding", "evidence-reader", f"{rbac}/v1",
           subjects=[{"kind": "ServiceAccount", "name": "evidence-reader", "namespace": NAMESPACE}],
           roleRef={"apiGroup": rbac, "kind": "Role", "name": "evidence-reader"})
    for kind, extra in (
        ("ClusterRole", {"rules": [{"apiGroups": [""], "resources": ["namespaces"],
                                   "resourceNames": [NAMESPACE], "verbs": ["get"]}]}),
        ("ClusterRoleBinding", {
            "subjects": [{"kind": "ServiceAccount", "name": "evidence-reader", "namespace": NAMESPACE}],
            "roleRef": {"apiGroup": rbac, "kind": "ClusterRole", "name": NAME},
        }),
    ):
        lab.kubectl("create", "-f", "-", payload=json.dumps({
            "apiVersion": f"{rbac}/v1", "kind": kind, "metadata": {"name": NAME}, **extra,
        }))
    create(lab, "ConfigMap", "collector-code", data={"collect.py": (HERE / "collect.py").read_text()})
    create(lab, "PersistentVolumeClaim", NAME,
           spec={"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "128Mi"}}})
    context = {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001,
               "seccompProfile": {"type": "RuntimeDefault"}}
    restricted = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                  "capabilities": {"drop": ["ALL"]}}
    store = {"name": "snapshots", "persistentVolumeClaim": {"claimName": NAME}}
    collector = {
        "restartPolicy": "Never", "serviceAccountName": "evidence-reader", "securityContext": context,
        "volumes": [store, {"name": "code", "configMap": {"name": "collector-code"}}],
        "containers": [{
            "name": "collector", "image": IMAGE, "command": ["python", "/case/collect.py"],
            "securityContext": restricted,
            "env": [{"name": key, "valueFrom": {"fieldRef": {"fieldPath": field}}}
                    for key, field in (("FIXTURE_NAMESPACE", "metadata.namespace"), ("FIXTURE_POD", "metadata.name"))],
            "volumeMounts": [{"name": "snapshots", "mountPath": "/snapshots"},
                             {"name": "code", "mountPath": "/case", "readOnly": True}],
        }],
    }
    create(lab, "CronJob", NAME, "batch/v1", spec={
        "schedule": "* * * * *", "timeZone": "Etc/UTC", "suspend": True, "startingDeadlineSeconds": 30,
        "concurrencyPolicy": "Forbid", "successfulJobsHistoryLimit": 3,
        "jobTemplate": {"metadata": {"labels": {"app": NAME}},
                        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90, "template": {"spec": collector}}},
    })
    create(lab, "Pod", "independent-reader", spec={
        "automountServiceAccountToken": False, "securityContext": context,
        "volumes": [store],
        "containers": [{"name": "reader", "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(600)"],
                        "securityContext": restricted,
                        "volumeMounts": [{"name": "snapshots", "mountPath": "/snapshots", "readOnly": True}]}],
    })
    kubectl(lab, "wait", "pod/independent-reader", "--for=condition=Ready", "--timeout=80s", timeout=90)


def scheduled_snapshot(lab, prior=None):
    cron = get_json(lab, "get", "cronjob", NAME)
    deadline = time.monotonic() + 140
    while time.monotonic() < deadline:
        jobs = get_json(lab, "get", "jobs", "-l", f"app={NAME}")["items"]
        for job in jobs:
            meta = job["metadata"]
            stamp = meta.get("annotations", {}).get("batch.kubernetes.io/cronjob-scheduled-timestamp")
            owner = any(ref["kind"] == "CronJob" and ref["uid"] == cron["metadata"]["uid"] and ref.get("controller")
                        for ref in meta.get("ownerReferences", []))
            if not owner or not stamp or (prior and stamp <= prior):
                continue
            status = job.get("status", {})
            if status.get("failed"):
                kubectl(lab, "logs", f"job/{meta['name']}", allow_failure=True)
                lab.block("The scheduled fixture collector failed")
            if status.get("succeeded") != 1:
                continue
            pods = get_json(lab, "get", "pods", "-l", f"batch.kubernetes.io/job-name={meta['name']}")["items"]
            owned = [p for p in pods if any(ref["kind"] == "Job" and ref["uid"] == meta["uid"]
                                            and ref.get("controller") for ref in p["metadata"].get("ownerReferences", []))]
            if len(owned) != 1:
                lab.block("Expected one Pod controlled by the scheduled fixture Job")
            pod = owned[0]["metadata"]["name"]
            produced = json.loads(kubectl(lab, "logs", pod).stdout)
            path = f"/snapshots/{pod}.json"
            retained = read_snapshot(lab, path)
            return stamp, path, produced, retained
        time.sleep(1)
    lab.block("Native CronJob did not produce a new completed scheduled fixture snapshot")


def read_snapshot(lab, path):
    return json.loads(kubectl(lab, "exec", "independent-reader", "--", "cat", path).stdout)


def age(snapshot):
    captured = datetime.fromisoformat(snapshot["collected_at"])
    return (datetime.now(timezone.utc) - captured).total_seconds()


def run(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    missing_api = lab.kubectl("get", "podsecuritystandards", "-o", "name", allow_failure=True)
    reported_absent = (missing_api.returncode != 0
                       and 'server doesn\'t have a resource type "podsecuritystandards"' in missing_api.stderr)
    lab.kubectl("label", "namespace", NAMESPACE, *(f"{key}={value}" for key, value in PSA.items()))
    labels = get_json(lab, "get", "namespace", NAMESPACE)["metadata"]["labels"]
    stored_labels = {key: labels.get(key) for key in PSA} == PSA
    lab.check("positive", "Pod Security Admission settings are available through Namespace labels",
              reported_absent and stored_labels,
              {"standalone_api_type_absent": reported_absent, "namespace_labels_confirmed": stored_labels})
    fixture = json.loads((HERE / "source-fixtures.json").read_text())
    kubectl(lab, "create", "-f", "-", payload=json.dumps(fixture))
    expected = {row["metadata"]["name"]: row["data"] for row in fixture["items"]}
    create(lab, "ConfigMap", "unlisted-neighbor", data={"allowed": "false"})
    configure(lab, expected)
    jobs = get_json(lab, "get", "jobs", "-l", f"app={NAME}")["items"]
    files = kubectl(lab, "exec", "independent-reader", "--", "ls", "-1", "/snapshots").stdout.splitlines()
    lab.check("red", "Suspended scheduling leaves the independent store without a snapshot",
              not jobs and not any(name.endswith(".json") for name in files),
              {"scheduled_jobs_absent": not jobs, "snapshots_absent": not any(name.endswith(".json") for name in files)})

    patch(lab, "cronjob", NAME, {"spec": {"suspend": False}})
    stamp, path, emitted, first = scheduled_snapshot(lab)
    patch(lab, "cronjob", NAME, {"spec": {"suspend": True}})
    first_fresh = 0 <= age(first) <= FRESHNESS
    exact_inputs = first["configs"] == expected and first["pod_security_admission"] == PSA
    denied_unlisted = first["rbac"] == {"unlisted_get": 403, "configmap_list": 403}
    lab.check("green", "A real scheduled Job captures exact named records and a separate Pod reads the fresh artifact",
              first_fresh and exact_inputs and denied_unlisted and first == emitted,
              {"fresh": first_fresh, "exact_catalog_and_crosswalk_records": exact_inputs,
               "scope_denials": denied_unlisted, "independent_read_matches": first == emitted})

    time.sleep(FRESHNESS + 1)
    stale = age(read_snapshot(lab, path)) > FRESHNESS
    lab.check("green", "The retained snapshot crosses the fixture freshness threshold during suspension",
              stale and get_json(lab, "get", "cronjob", NAME)["spec"]["suspend"],
              {"snapshot_stale": stale, "fixture_max_age_seconds": FRESHNESS})

    patch(lab, "configmap", "synthetic-control-record", {"data": {"evidence_revision": "r2"}})
    expected["synthetic-control-record"]["evidence_revision"] = "r2"
    patch(lab, "cronjob", NAME, {"spec": {"suspend": False}})
    next_stamp, next_path, next_emitted, second = scheduled_snapshot(lab, prior=stamp)
    new_exact = (second == next_emitted and second["configs"] == expected
                 and second["pod_security_admission"] == PSA)
    kept_old = read_snapshot(lab, path) == first
    new_fresh = 0 <= age(second) <= FRESHNESS
    (lab.evidence / "scheduled-evidence-history.json").write_text(json.dumps([
        {"scheduled_at": stamp, "store_path": path, "snapshot": first},
        {"scheduled_at": next_stamp, "store_path": next_path, "snapshot": second},
    ], indent=2) + "\n")
    lab.check("positive", "Resuming scheduling captures the revised source and preserves the earlier artifact",
              new_exact and kept_old and new_fresh and next_path != path,
              {"revised_inputs_exact": new_exact, "older_artifact_retained": kept_old,
               "new_artifact_fresh": new_fresh})
    runpy.run_path(str(HERE / "scoped" / "case.py"))["run"](lab)
