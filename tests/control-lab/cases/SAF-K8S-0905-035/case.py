"""Verify automatic rollout rollback and independent live traffic recovery."""
import json
from pathlib import Path
import time

from fixtures import container, pod

HERE = Path(__file__).parent
IMAGE = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
ACTOR = "fixture-rollout-controller"
ROLLBACK = "saf.example/automatic-rollback"
SCOPE = (
    "A fresh Kind v1.36.1 cluster runs stable and candidate HTTP fixtures through live Kubernetes "
    "Services. A scoped rollout-analysis Job observes four candidate requests per episode. "
    "It atomically changes the route and records a reason if at least three requests are HTTP "
    "errors or cross the fixture latency limit. Independent live requests read the stable response "
    "after each automatic change. Production rollout controllers, real model health, candidate "
    "scaling, transaction recovery and policy deployment remain open."
)


def _create_service(lab, name, app):
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                "spec": {"selector": {"app": app}, "ports": [{"port": 8080, "targetPort": 8080}]}})


def _process(script, *, params=None, readiness=False):
    return container("app", image=IMAGE, command=["python", "-B", "/fixture/" + script],
                     env=[{"name": k, "value": str(v)} for k, v in (params or {}).items()],
                     volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True}],
                     resources={"requests": {"cpu": "15m", "memory": "24Mi"},
                                "limits": {"cpu": "200m", "memory": "64Mi"}},
                     **({"readinessProbe": {"httpGet": {"path": "/health", "port": 8080},
                                            "periodSeconds": 1}} if readiness else {}))


CODE = {"name": "code", "configMap": {"name": "rollout-fixture"}}


def _install(lab):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "rollout-fixture"},
                "immutable": True, "data": {name: (HERE / name).read_text() for name in ("worker.py", "controller.py")}})
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": ACTOR}})
    api = "rbac.authorization.k8s.io/v1"
    lab.create({"apiVersion": api, "kind": "Role", "metadata": {"name": ACTOR},
                "rules": [{"apiGroups": [""], "resources": ["services"], "resourceNames": ["model-route"],
                           "verbs": ["get", "patch"]}]})
    lab.create({"apiVersion": api, "kind": "RoleBinding", "metadata": {"name": ACTOR},
                "subjects": [{"kind": "ServiceAccount", "name": ACTOR, "namespace": "saf-test"}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ACTOR}})
    for name in ("stable", "candidate"):
        selector = {"app": name}
        model = _process("worker.py", params={"VERSION": name, "MODE": "healthy"}, readiness=True)
        lab.create({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
                    "spec": {"replicas": 1, "selector": {"matchLabels": selector},
                             "template": {"metadata": {"labels": selector},
                                          "spec": {"automountServiceAccountToken": False,
                                                   "terminationGracePeriodSeconds": 1,
                                                   "containers": [model], "volumes": [CODE]}}}})
        _create_service(lab, name, name)
    _create_service(lab, "model-route", "candidate")
    lab.create(pod("observer", [container("probe", image=IMAGE, command=["sleep", "900"])],
                   automountServiceAccountToken=False))
    for name in ("stable", "candidate"):
        _ready(lab, name)
    lab.kubectl("wait", "--for=condition=Ready", "pod/observer", "--timeout=65s", timeout=70)


def _ready(lab, name):
    lab.kubectl("rollout", "status", "deployment/" + name, "--timeout=65s", timeout=70)


def _route(lab):
    client = """import json
from urllib.request import urlopen
from urllib.error import HTTPError
try:
    with urlopen('http://model-route:8080/infer', timeout=3) as r:
        print(json.dumps([r.status,r.read().decode()]))
except HTTPError as r:
    print(json.dumps([r.code,r.read().decode()]))"""
    response = lab.kubectl("exec", "pod/observer", "--", "python", "-B", "-c", client, timeout=8,
                           allow_failure=True)
    return json.loads(response.stdout) if response.returncode == 0 else None


def _await_route(lab, expected):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if _route(lab) == expected:
            return True
        time.sleep(0.3)
    return False


def _arm(lab, mode):
    lab.kubectl("set", "env", "deployment/candidate", "MODE=" + mode)
    _ready(lab, "candidate")
    patch = {"metadata": {"annotations": {ROLLBACK: None}}, "spec": {"selector": {"app": "candidate"}}}
    lab.kubectl("patch", "service/model-route", "--type=merge", "-p", json.dumps(patch))
    before = [503, "candidate"] if mode == "error" else [200, "candidate"]
    if not _await_route(lab, before):
        lab.block("The current rollout did not actually serve from its candidate")
    return before


def _episode(lab, name, enabled):
    app = _process("controller.py", params={"ENABLED": str(enabled).lower()})
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 65,
                         "template": {"spec": {"serviceAccountName": ACTOR, "restartPolicy": "Never",
                                               "containers": [app], "volumes": [CODE]}}}})
    lab.kubectl("wait", "--for=condition=Complete", "job/" + name, "--timeout=68s", timeout=72)
    report = json.loads(lab.kubectl("logs", "job/" + name).stdout)
    service = json.loads(lab.kubectl("get", "service/model-route", "-o", "json").stdout)
    decision = service["metadata"].get("annotations", {}).get(ROLLBACK)
    return report, json.loads(decision) if decision else None


def run(lab):
    _install(lab)
    evidence = {}
    for name, mode, enabled, reason, phase in (
        ("healthy", "healthy", True, "healthy", "positive"),
        ("control-off", "error", False, "error-rate", "red"),
        ("error-trigger", "error", True, "error-rate", "green"),
        ("latency-trigger", "slow", True, "latency", "green"),
    ):
        initial = _arm(lab, mode)
        report, recorded = _episode(lab, name, enabled)
        rollback = phase == "green"
        endpoint = [200, "stable"] if rollback else initial
        matches = _await_route(lab, endpoint)
        record_exact = recorded == report if rollback else recorded is None
        complete = (len(report["samples"]) == 4 and report["reason"] == reason
                    and report["rollback"] == rollback and record_exact and matches)
        lab.check(phase, "Live routing and recorded analysis agree for " + name, complete,
                  {"analysis_reason": report["reason"], "automatic_rollback": report["rollback"],
                   "record_matches_expected": record_exact, "live_endpoint": endpoint,
                   "live_response_verified": matches, "sample_count": len(report["samples"])})
        evidence[name] = {"analysis": report, "stored_decision": recorded, "route_after": endpoint}
    (lab.evidence / "canary-rollback.json").write_text(json.dumps(evidence, indent=2) + "\n")
