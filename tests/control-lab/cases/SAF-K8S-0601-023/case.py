"""Exercise a live scheduled rotation and propagation path with inert markers."""
from datetime import datetime, timedelta, timezone
import json
import time

from fixtures import container, pod, ready

SCOPE = (
    "One disposable kind namespace. A real Kubernetes CronJob updates a synthetic "
    "version marker using a dedicated authorized ServiceAccount. Two running Pods "
    "observe the update through ConfigMap volume projection. Registry credentials, "
    "revocation and private image authentication require separate evidence."
)
CLI = "registry.k8s.io/kubectl:v1.36.1@sha256:d08f476d04d0e30f426f06bc6ff6c38913aaa4591943046b77e2f74a72d3611c"
MARKER = "rotation-version"
WRITER = "marker-rotator"
READERS = ("marker-reader-a", "marker-reader-b")
LABEL = "saf-k8s.example/rotation=fixture"


def get(lab, *fields):
    return json.loads(lab.kubectl("get", *fields, "-o", "json").stdout)


def current(lab):
    return get(lab, "configmap", MARKER)["data"]["version"]


def read_markers(lab):
    return [lab.kubectl("exec", name, "--", "cat", "/fixture/version").stdout.strip()
            for name in READERS]


def install_writer(lab):
    objects = (
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": WRITER}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": WRITER},
         "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [MARKER],
                    "verbs": ["get", "patch"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": WRITER},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": WRITER},
         "subjects": [{"kind": "ServiceAccount", "name": WRITER, "namespace": "saf-test"}]},
    )
    for obj in objects:
        lab.create(obj)
    command = ["/bin/kubectl", "-n", "saf-test", "patch", "configmap", MARKER, "--type=merge",
               "-p", json.dumps({"data": {"version": "fixture-v2"}}), "-o", "name"]
    workload = container("rotator", image=CLI, command=command)
    return lab.create({
        "apiVersion": "batch/v1", "kind": "CronJob",
        "metadata": {"name": WRITER},
        "spec": {
            "schedule": "* * * * *", "timeZone": "Etc/UTC", "suspend": True,
            "startingDeadlineSeconds": 40, "concurrencyPolicy": "Forbid",
            "successfulJobsHistoryLimit": 1,
            "jobTemplate": {"metadata": {"labels": {"saf-k8s.example/rotation": "fixture"}},
                            "spec": {"activeDeadlineSeconds": 80, "backoffLimit": 0, "template": {
                                "spec": {"serviceAccountName": WRITER, "restartPolicy": "Never",
                                         "containers": [workload]}}}},
        },
    })["metadata"]["uid"]


def completed_job(lab, owner_id):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        for item in get(lab, "jobs", "-l", LABEL)["items"]:
            if not any(owner.get("uid") == owner_id and owner.get("kind") == "CronJob"
                       for owner in item["metadata"].get("ownerReferences", [])):
                continue
            conditions = item["status"].get("conditions", [])
            if any(c["type"] == "Failed" and c["status"] == "True" for c in conditions):
                lab.block("The scheduled marker update Job failed")
            when = item["metadata"].get("annotations", {}).get("batch.kubernetes.io/cronjob-scheduled-timestamp")
            if when and any(c["type"] == "Complete" and c["status"] == "True" for c in conditions):
                return datetime.fromisoformat(when.replace("Z", "+00:00"))
        time.sleep(2)
    lab.block("No controller-owned marker update Job completed")


def run(lab):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": MARKER},
                "data": {"version": "fixture-v1"}})
    originals = {}
    for name in READERS:
        reader = container("reader", volumeMounts=[{"name": "marker", "mountPath": "/fixture", "readOnly": True}])
        value = lab.create(pod(name, [reader], automountServiceAccountToken=False,
                               volumes=[{"name": "marker", "configMap": {"name": MARKER}}]))
        originals[name] = value["metadata"]["uid"]
        ready(lab, name)

    owner_id = install_writer(lab)
    now = datetime.now(timezone.utc)
    schedule = now.replace(second=0, microsecond=0) + timedelta(minutes=1)
    deadline = schedule + timedelta(seconds=5)
    time.sleep(max(0, (deadline - now).total_seconds()))
    initial = read_markers(lab)
    jobs = get(lab, "jobs", "-l", LABEL)["items"]
    lab.check("red", "A suspended schedule leaves both projected markers and Job inventory unchanged",
              current(lab) == "fixture-v1" and initial == ["fixture-v1"] * 2 and not jobs,
              {"reader_versions": initial, "job_count": len(jobs)})

    old_fixture_expires = datetime.now(timezone.utc) + timedelta(minutes=5)
    lab.kubectl("patch", "cronjob", WRITER, "--type=merge", "-p", '{"spec":{"suspend":false}}')
    due = completed_job(lab, owner_id)
    rotated = current(lab)
    timely = due < old_fixture_expires and datetime.now(timezone.utc) < old_fixture_expires
    lab.check("green", "The CronJob controller schedules the authorized update before fixture expiry",
              timely and rotated == "fixture-v2",
              {"controller_owned_job_completed": True, "fixture_deadline_met": timely,
               "marker_version": rotated})

    projection_deadline = time.monotonic() + 115
    observed = []
    while time.monotonic() < projection_deadline:
        observed = read_markers(lab)
        if observed == ["fixture-v2"] * 2:
            break
        time.sleep(3)
    same_pods = all(get(lab, "pod", name)["metadata"]["uid"] == originals[name] for name in READERS)
    lab.check("positive", "Both original running Pods receive the refreshed marker",
              observed == ["fixture-v2"] * 2 and same_pods,
              {"reader_versions": observed, "original_pods": same_pods})
