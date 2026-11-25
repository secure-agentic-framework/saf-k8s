"""Exercise authorized workload actions with bounded synthetic budget evidence."""

import json
import time

from fixtures import container

NAMESPACE = "saf-budget-action-fixture"
ACCOUNT = "budget-action"
MANAGED_JOB = "owned-training"
MANAGED_DEPLOYMENT = "owned-serving"
COMPARATOR = "unrelated-serving"
LIMIT = 100
ALERT_AT = 80


def create(lab, api_version, kind, name, **fields):
    metadata = {"name": name}
    if kind != "Namespace":
        metadata["namespace"] = NAMESPACE
    item = {"apiVersion": api_version, "kind": kind, "metadata": metadata, **fields}
    lab.kubectl("create", "-n", NAMESPACE, "-f", "-", "-o", "name", payload=json.dumps(item))


def wait_for(lab, predicate, label, timeout=90):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(1)
    lab.block(f"Timed out waiting for {label}")


def read(lab, resource, name):
    result = lab.kubectl("get", resource, name, "-n", NAMESPACE, "-o", "json")
    return json.loads(result.stdout)


def replicas(lab, name):
    return read(lab, "deployment", name)["status"].get("readyReplicas", 0)


def active_job(lab):
    job = read(lab, "job", MANAGED_JOB)
    pods = json.loads(lab.kubectl(
        "get", "pods", "-n", NAMESPACE, "-l", f"batch.kubernetes.io/job-name={MANAGED_JOB}",
        "-o", "json",).stdout)["items"]
    return job["status"].get("active", 0), len(pods)


def update_workload(lab, resource, name, change, *args, allow_failure=False):
    return lab.kubectl("--as", f"system:serviceaccount:{NAMESPACE}:{ACCOUNT}",
                       "patch", resource, name, "-n", NAMESPACE, "--type=merge",
                       "-p", json.dumps({"spec": change}), *args,
                       allow_failure=allow_failure)


def create_workloads(lab):
    create(lab, "v1", "Namespace", NAMESPACE)
    create(lab, "v1", "ServiceAccount", ACCOUNT, automountServiceAccountToken=False)
    create(lab, "rbac.authorization.k8s.io/v1", "Role", ACCOUNT, rules=[
        {"apiGroups": ["batch"], "resources": ["jobs"],
         "resourceNames": [MANAGED_JOB], "verbs": ["get", "patch"]},
        {"apiGroups": ["apps"], "resources": ["deployments"],
         "resourceNames": [MANAGED_DEPLOYMENT, COMPARATOR], "verbs": ["get"]},
        {"apiGroups": ["apps"], "resources": ["deployments/scale"],
         "resourceNames": [MANAGED_DEPLOYMENT, COMPARATOR], "verbs": ["get"]},
        {"apiGroups": ["apps"], "resources": ["deployments/scale"],
         "resourceNames": [MANAGED_DEPLOYMENT], "verbs": ["patch"]},
    ])
    create(lab, "rbac.authorization.k8s.io/v1", "RoleBinding", ACCOUNT,
           roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ACCOUNT},
           subjects=[{"kind": "ServiceAccount", "name": ACCOUNT, "namespace": NAMESPACE}])
    job_pod = {"restartPolicy": "Never", "automountServiceAccountToken": False,
               "containers": [container("training")]}
    create(lab, "batch/v1", "Job", MANAGED_JOB, spec={
        "backoffLimit": 0, "activeDeadlineSeconds": 600, "template": {"spec": job_pod},
    })
    for name in (MANAGED_DEPLOYMENT, COMPARATOR):
        labels = {"app.kubernetes.io/name": name}
        create(lab, "apps/v1", "Deployment", name, spec={
            "replicas": 1, "selector": {"matchLabels": labels},
            "template": {"metadata": {"labels": labels}, "spec": {
                "automountServiceAccountToken": False, "containers": [container("serving")]}},
        })
        lab.kubectl("rollout", "status", f"deployment/{name}", "-n", NAMESPACE,
                    "--timeout=90s", timeout=95)
    wait_for(lab, lambda: active_job(lab) == (1, 1), "the original active fixture Job")


def decide(lab, cost, current, actions_armed):
    """Evaluate one synthetic observation and apply only the two allowed actions."""
    if not current or cost < ALERT_AT:
        return "hold"
    if cost < LIMIT or not actions_armed:
        return "alert"
    update_workload(lab, "job", MANAGED_JOB, {"suspend": True})
    update_workload(lab, "deployment", MANAGED_DEPLOYMENT, {"replicas": 0},
                    "--subresource=scale")
    return "enforced"


def run(lab):
    create_workloads(lab)

    advisory = decide(lab, LIMIT, current=True, actions_armed=False)
    lab.check("red", "A synthetic budget threshold without the actuator leaves both workloads running",
              advisory == "alert" and active_job(lab) == (1, 1)
              and replicas(lab, MANAGED_DEPLOYMENT) == 1,
              {"advisory": advisory, "active_job": active_job(lab) == (1, 1),
               "serving_ready": replicas(lab, MANAGED_DEPLOYMENT) == 1})

    approaching = decide(lab, ALERT_AT, current=True, actions_armed=True)
    stale = decide(lab, LIMIT, current=False, actions_armed=True)
    lab.check("positive", "An approaching threshold yields an advisory and stale observations do not trigger workload actions",
              approaching == "alert" and stale == "hold"
              and active_job(lab) == (1, 1) and replicas(lab, MANAGED_DEPLOYMENT) == 1,
              {"approaching": approaching, "stale": stale, "workloads_active": active_job(lab) == (1, 1)
               and replicas(lab, MANAGED_DEPLOYMENT) == 1})

    enforced = decide(lab, LIMIT, current=True, actions_armed=True)
    wait_for(lab, lambda: active_job(lab) == (0, 0), "suspended Job Pod removal")
    wait_for(lab, lambda: replicas(lab, MANAGED_DEPLOYMENT) == 0, "Deployment scale-down")
    job = read(lab, "job", MANAGED_JOB)
    deployment = read(lab, "deployment", MANAGED_DEPLOYMENT)
    lab.check("green", "A current threshold observation suspends the named Job and reduces the named Deployment to zero",
              enforced == "enforced" and job["spec"].get("suspend") is True
              and active_job(lab) == (0, 0) and deployment["spec"].get("replicas") == 0
              and replicas(lab, MANAGED_DEPLOYMENT) == 0,
              {"enforced": enforced == "enforced", "job_suspended": job["spec"].get("suspend") is True,
               "active_job_pods": active_job(lab)[1], "ready_serving_replicas": replicas(lab, MANAGED_DEPLOYMENT)})

    denied = update_workload(lab, "deployment", COMPARATOR, {"replicas": 0}, "--subresource=scale",
                             allow_failure=True)
    lab.check("positive", "The actual API refuses actuator access to an unrelated Deployment and its Pod remains ready",
              denied.returncode != 0 and "cannot patch resource" in denied.stderr.lower()
              and replicas(lab, COMPARATOR) == 1,
              {"authorization_refused": denied.returncode != 0 and "cannot patch resource" in denied.stderr.lower(),
               "unrelated_ready": replicas(lab, COMPARATOR) == 1})
