"""Run a real token-authenticated budget-event evaluator Pod in the owned cluster."""

import importlib.util
import json
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-budget-0703-014"
ACTOR = "budget-response"
MANAGED_JOB = "owned-training"
OTHER_JOB = "unrelated-training"
NEGATIVE_EVALUATOR = "budget-evaluator-negative"
ENFORCING_EVALUATOR = "budget-evaluator-enforce"
EVENTS = ("red-unarmed", "warning", "stale", "wrong-target", "green-armed")
MARKERS = tuple("marker-" + name for name in EVENTS)
PYTHON_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"


def create(lab, api_version, kind, name, **fields):
    item = {"apiVersion": api_version, "kind": kind,
            "metadata": {"name": name, "namespace": NAMESPACE}, **fields}
    return lab.kubectl("create", "-n", NAMESPACE, "-f", "-", "-o", "name",
                       payload=json.dumps(item))


def read(lab, resource, name):
    return json.loads(lab.kubectl("get", resource, name, "-n", NAMESPACE, "-o", "json").stdout)


def pods(lab, job_name):
    result = lab.kubectl(
        "get", "pods", "-n", NAMESPACE, "-l",
        f"batch.kubernetes.io/job-name={job_name}", "-o", "json",
    )
    return json.loads(result.stdout)["items"]


def wait_for(lab, predicate, label, timeout=60):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(1)
    lab.block(f"Timed out waiting for {label}")


def create_marker(lab, name):
    create(lab, "v1", "ConfigMap", name, data={})


def create_event(lab, name, spend, freshness="current", target=MANAGED_JOB, armed=True):
    create(lab, "v1", "ConfigMap", name, data={
        "event_id": name,
        "scope": NAMESPACE,
        "target_job": target,
        "spend_units": str(spend),
        "alert_units": "80",
        "hard_limit_units": "100",
        "freshness": freshness,
        "actions_armed": "true" if armed else "false",
    })
    return read(lab, "configmap", name)["data"]


def create_fixture(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("label", "namespace", NAMESPACE, "pod-security.kubernetes.io/enforce=restricted")
    create(lab, "v1", "ServiceAccount", ACTOR, automountServiceAccountToken=False)
    create(lab, "rbac.authorization.k8s.io/v1", "Role", ACTOR, rules=[
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": list(EVENTS),
         "verbs": ["get"]},
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": list(MARKERS),
         "verbs": ["patch"]},
        {"apiGroups": ["batch"], "resources": ["jobs"],
         "resourceNames": [MANAGED_JOB], "verbs": ["patch"]},
    ])
    create(lab, "rbac.authorization.k8s.io/v1", "RoleBinding", ACTOR,
           roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ACTOR},
           subjects=[{"kind": "ServiceAccount", "name": ACTOR, "namespace": NAMESPACE}])

    for name in (MANAGED_JOB, OTHER_JOB):
        create(lab, "batch/v1", "Job", name, spec={
            "backoffLimit": 0,
            "activeDeadlineSeconds": 900,
            "template": {"spec": {
                "restartPolicy": "Never",
                "automountServiceAccountToken": False,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                    "runAsGroup": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{
                    "name": "inert-training-marker",
                    "image": "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec",
                    "command": ["sh", "-c", "sleep 3600"],
                    "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                  "limits": {"cpu": "50m", "memory": "32Mi"}},
                    "securityContext": {"allowPrivilegeEscalation": False,
                                         "readOnlyRootFilesystem": True,
                                         "capabilities": {"drop": ["ALL"]}},
                }],
            }},
        })

    for name in MARKERS:
        create_marker(lab, name)
    create_event(lab, "red-unarmed", 100, armed=False)
    create_event(lab, "warning", 80)
    create_event(lab, "stale", 100, freshness="stale")
    create_event(lab, "wrong-target", 100, target=OTHER_JOB)
    create_event(lab, "green-armed", 100)
    wait_for(lab, lambda: len(pods(lab, MANAGED_JOB)) == 1, "owned inert Job Pod")
    wait_for(lab, lambda: len(pods(lab, OTHER_JOB)) == 1, "unrelated inert Job Pod")
    wait_for(lab, lambda: lab.kubectl("get", "configmap", "kube-root-ca.crt", "-n", NAMESPACE,
                                      allow_failure=True).returncode == 0,
             "namespace API CA bundle")
    source = (HERE / "worker.py").read_text(encoding="utf-8")
    create(lab, "v1", "ConfigMap", "budget-evaluator-code", immutable=True, data={"worker.py": source})


def create_evaluator(lab, evaluator_name, events):
    pod = {
        "restartPolicy": "Never",
        "serviceAccountName": ACTOR,
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                            "fsGroup": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
        "volumes": [
            {"name": "worker", "configMap": {"name": "budget-evaluator-code",
                                                  "defaultMode": 292}},  # 0444
            {"name": "api-credentials", "projected": {
                "defaultMode": 288,  # 0440, readable by the evaluator fsGroup only
                "sources": [
                    {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
                    {"configMap": {"name": "kube-root-ca.crt",
                                    "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
                ],
            }},
        ],
        "containers": [{
            "name": "budget-evaluator",
            "image": PYTHON_IMAGE,
            "imagePullPolicy": "IfNotPresent",
            "command": ["python3", "-B", "/worker/worker.py"],
            "env": [{"name": "EVENT_NAMES", "value": ",".join(events)}],
            "resources": {"requests": {"cpu": "20m", "memory": "32Mi"},
                          "limits": {"cpu": "100m", "memory": "96Mi"}},
            "securityContext": {"allowPrivilegeEscalation": False,
                                 "readOnlyRootFilesystem": True,
                                 "capabilities": {"drop": ["ALL"]}},
            "volumeMounts": [
                {"name": "worker", "mountPath": "/worker", "readOnly": True},
                {"name": "api-credentials", "mountPath": "/var/run/saf-api", "readOnly": True},
            ],
        }],
    }
    create(lab, "batch/v1", "Job", evaluator_name, spec={
        "backoffLimit": 0,
        "activeDeadlineSeconds": 120,
        "ttlSecondsAfterFinished": 300,
        "template": {"metadata": {"labels": {"app": evaluator_name}}, "spec": pod},
    })
    result = lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Complete", f"job/{evaluator_name}",
                         "--timeout=120s", timeout=125, allow_failure=True)
    if result.returncode:
        lab.kubectl("-n", NAMESPACE, "logs", f"job/{evaluator_name}", allow_failure=True)
        lab.block("The projected-token budget evaluator Job did not complete")
    job = read(lab, "job", evaluator_name)
    if job.get("status", {}).get("succeeded") != 1:
        lab.block("The case-local projected-token evaluator did not complete successfully")


def marker(lab, event_name):
    return read(lab, "configmap", "marker-" + event_name).get("data", {})


def evaluator_identity(lab, evaluator_name):
    items = pods(lab, evaluator_name)
    if len(items) != 1:
        return False
    spec = items[0].get("spec", {})
    projected = [volume.get("projected", {}) for volume in spec.get("volumes", [])]
    token_sources = [source.get("serviceAccountToken", {})
                     for volume in projected for source in volume.get("sources", [])]
    return (
        spec.get("serviceAccountName") == ACTOR
        and spec.get("automountServiceAccountToken") is False
        and any(source.get("expirationSeconds") == 600 and source.get("path") == "token"
                for source in token_sources)
    )


def run(lab):
    create_fixture(lab)
    create_evaluator(lab, NEGATIVE_EVALUATOR, EVENTS[:-1])

    red = marker(lab, "red-unarmed")
    red_target = read(lab, "job", MANAGED_JOB)
    actual_identity = evaluator_identity(lab, NEGATIVE_EVALUATOR)
    lab.check(
        "red", "The evaluator's projected ServiceAccount token records an unarmed threshold without suspending the target",
        red.get("event_id") == "red-unarmed" and red.get("decision") == "alert"
        and red.get("actor") == f"system:serviceaccount:{NAMESPACE}:{ACTOR}"
        and actual_identity
        and red_target["spec"].get("suspend") is not True
        and len(pods(lab, MANAGED_JOB)) == 1,
        {"marker_recorded": red.get("event_id") == "red-unarmed",
         "decision": red.get("decision"),
         "projected_actor": red.get("actor") == f"system:serviceaccount:{NAMESPACE}:{ACTOR}",
         "pod_service_account_and_projection": actual_identity,
         "target_active": len(pods(lab, MANAGED_JOB)) == 1},
    )

    warning = marker(lab, "warning")
    stale = marker(lab, "stale")
    wrong_target = marker(lab, "wrong-target")
    unchanged = (read(lab, "job", MANAGED_JOB)["spec"].get("suspend") is not True
                 and read(lab, "job", OTHER_JOB)["spec"].get("suspend") is not True
                 and len(pods(lab, MANAGED_JOB)) == 1 and len(pods(lab, OTHER_JOB)) == 1)
    lab.check(
        "positive", "Warning, stale, and mismatched-target events leave both owned Jobs unchanged",
        warning.get("decision") == "alert" and stale.get("decision") == "hold"
        and wrong_target.get("decision") == "hold"
        and warning.get("actor") == stale.get("actor") == wrong_target.get("actor")
        == f"system:serviceaccount:{NAMESPACE}:{ACTOR}"
        and unchanged,
        {"warning": warning.get("decision"), "stale": stale.get("decision"),
         "wrong_target": wrong_target.get("decision"), "both_jobs_unchanged": unchanged},
    )

    create_evaluator(lab, ENFORCING_EVALUATOR, EVENTS[-1:])
    enforcing_identity = evaluator_identity(lab, ENFORCING_EVALUATOR)
    green = marker(lab, "green-armed")
    wait_for(lab, lambda: len(pods(lab, MANAGED_JOB)) == 0, "suspended target Job Pod removal")
    owned = read(lab, "job", MANAGED_JOB)
    other = read(lab, "job", OTHER_JOB)
    lab.check(
        "green", "The evaluator suspends only the approved Job; a server dry-run patch of the other Job is forbidden",
        green.get("decision") == "enforced" and green.get("other_target_denied") == "true"
        and enforcing_identity
        and owned["spec"].get("suspend") is True and len(pods(lab, MANAGED_JOB)) == 0
        and other["spec"].get("suspend") is not True and len(pods(lab, OTHER_JOB)) == 1,
        {"decision": green.get("decision"), "other_target_denied": green.get("other_target_denied"),
         "owned_suspended": owned["spec"].get("suspend") is True,
         "owned_pods": len(pods(lab, MANAGED_JOB)),
         "unrelated_active": len(pods(lab, OTHER_JOB)) == 1},
    )
