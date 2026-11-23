"""Downstream normalized registry-event alert and review fixture."""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PORT = 8080
PYTHON_IMAGE = (
    "docker.io/library/python:3.13.2-alpine@sha256:"
    "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
)
REVIEW = "registry-alert-audit-003"
SCOPE = (
    "A disposable Kind cluster runs a case-owned monitor after the normalized forwarded-event boundary. "
    "Fixed registry events exercise sensitive-operation rules, a reported anomalous pull, source-label validation, "
    "out-of-scope handling and replay deduplication. Kubernetes RBAC restricts writing the named analyst disposition. "
    "Provider event completeness, real anomaly detection, durable SIEM storage, analyst response and production roles "
    "require separate evidence."
)


def _create(lab, resource):
    lab.kubectl("create", "-f", "-", payload=json.dumps(resource))


def _container(name, *, command, ports=None, mounts):
    item = {
        "name": name,
        "image": PYTHON_IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "readOnlyRootFilesystem": True,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "resources": {
            "requests": {"cpu": "15m", "memory": "32Mi"},
            "limits": {"cpu": "250m", "memory": "128Mi"},
        },
    }
    item["command"] = command
    if ports is not None:
        item["ports"] = ports
    item["volumeMounts"] = mounts
    return item


def _deployment(name, container, volumes):
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                        "fsGroup": 65534},
                    "containers": [container],
                    "volumes": volumes,
                },
            },
        },
    }


def _setup(lab):
    scripts = {name: (HERE / name).read_text() for name in ("monitor.py", "fixture.py", "events.json")}
    _create(lab, {
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "audit-review-code"},
        "immutable": True, "data": scripts,
    })
    code_volume = {"name": "code", "configMap": {"name": "audit-review-code"}}
    code_mount = {"name": "code", "mountPath": "/app", "readOnly": True}
    state_volume = {"name": "state", "emptyDir": {"medium": "Memory", "sizeLimit": "8Mi"}}
    monitor = _container("monitor", command=["python", "-B", "/app/monitor.py"],
                         ports=[{"name": "http", "containerPort": PORT}],
                         mounts=[code_mount, {"name": "state", "mountPath": "/state"}])
    monitor["readinessProbe"] = {"httpGet": {"path": "/health", "port": "http"}, "periodSeconds": 1}
    _create(lab, _deployment("audit-monitor", monitor, [code_volume, state_volume]))
    _create(lab, {
        "apiVersion": "v1", "kind": "Service", "metadata": {"name": "audit-monitor"},
        "spec": {"selector": {"app": "audit-monitor"},
                 "ports": [{"name": "http", "port": PORT, "targetPort": PORT}]},
    })
    _create(lab, _deployment(
        "audit-fixture",
        _container("fixture", command=["python", "-c", "import time; time.sleep(3600)"],
                   mounts=[code_mount]),
        [code_volume],
    ))
    for name in ("audit-monitor", "audit-fixture"):
        lab.kubectl("rollout", "status", f"deployment/{name}", "--timeout=90s", timeout=100)


def _json_exec(lab, argv):
    result = lab.kubectl("exec", "deployment/audit-fixture", "--", *argv)
    try:
        return json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        lab.block(f"Fixture returned invalid JSON: {exc}")


def check_events(lab, observations):
    baseline = observations["baseline"]
    enforced = observations["enforced"]
    replayed = observations["replayed"]
    events = [f"audit-{n:03d}" for n in range(1, 9)]
    expected_rules = {
        "audit-001": ("sensitive-publish", "fixture-publisher"),
        "audit-003": ("anomalous-pull", "fixture-reader"),
        "audit-004": ("sensitive-delete", "fixture-maintainer"),
        "audit-005": ("sensitive-permission-change", "fixture-maintainer"),
        "audit-006": ("sensitive-administration", "fixture-admin"),
    }
    expected = {"alert-" + event: {"event_id": event, "rule": rule,
                                    "actor": actor, "repository": "saf-test/model-a"}
                for event, (rule, actor) in expected_rules.items()}
    lab.check("red", "The inactive monitor receives all eight normalized events without alerting",
              baseline["events"] == events and baseline["alerts"] == {}
              and baseline["quiet"] == events and baseline["duplicates"] == 0,
              baseline)
    lab.check("green", "The same event corpus produces the five scoped alerts and leaves ordinary and out-of-scope events quiet",
              enforced["events"] == events and enforced["input_sha256"] == baseline["input_sha256"]
              and enforced["alerts"] == expected
              and enforced["quiet"] == ["audit-002", "audit-007", "audit-008"]
              and enforced["duplicates"] == 0,
              enforced)
    lab.check("positive", "Replay preserves exactly those alerts and a request with incorrect source metadata is rejected",
              replayed == {**enforced, "duplicates": len(events)}
              and observations["invalid_source"] == {"status": 422, "body": {"error": "invalid-event-provenance"}},
              {"replayed": replayed, "invalid_source": observations["invalid_source"]})


def review_alert(lab, alert):
    identity = alert["event_id"]
    start = {"alert_id": "alert-" + identity, "disposition": "unreviewed"}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": REVIEW}, "data": start})
    group = "rbac.authorization.k8s.io"
    for identity, verbs in (("audit-observer", ["get"]), ("audit-analyst", ["get", "patch"])):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": identity}})
        lab.create({"apiVersion": f"{group}/v1", "kind": "Role", "metadata": {"name": identity},
                    "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [REVIEW],
                               "verbs": verbs}]})
        lab.create({"apiVersion": f"{group}/v1", "kind": "RoleBinding", "metadata": {"name": identity},
                    "subjects": [{"kind": "ServiceAccount", "name": identity, "namespace": "saf-test"}],
                    "roleRef": {"apiGroup": group, "kind": "Role", "name": identity}})

    def get_record():
        return json.loads(lab.kubectl("get", f"configmap/{REVIEW}", "-o", "json").stdout)["data"]

    update = json.dumps({"data": {"disposition": "reviewed-benign-fixture"}})
    command = ("patch", f"configmap/{REVIEW}", "--type=merge", "-p", update, "-o", "json")
    denied = lab.kubectl(*command, "--as=system:serviceaccount:saf-test:audit-observer", allow_failure=True)
    forbidden = denied.returncode != 0 and "Forbidden" in denied.stderr and 'cannot patch resource "configmaps"' in denied.stderr
    unchanged = get_record() == start
    lab.check("green", "The ordinary Kubernetes account cannot change the existing alert disposition",
              forbidden and unchanged, {"forbidden": forbidden, "unchanged": unchanged})

    lab.kubectl(*command, "--as=system:serviceaccount:saf-test:audit-analyst")
    stored = get_record()
    lab.check("positive", "The scoped analyst can save a disposition and an independent read confirms the same alert identifier",
              stored == {**start, "disposition": "reviewed-benign-fixture"}, stored)
    return {"ordinary_forbidden": forbidden, "after_denial_unchanged": unchanged, "stored": stored}


def run(lab):
    _setup(lab)
    observations = _json_exec(lab, ["python", "-B", "/app/fixture.py", f"http://audit-monitor:{PORT}"])
    check_events(lab, observations)
    disposition = review_alert(lab, observations["enforced"]["alerts"]["alert-audit-003"])
    (lab.evidence / "normalized-audit-alert-review.json").write_text(
        json.dumps({"events": observations, "analyst_review": disposition}, indent=2, sort_keys=True) + "\n")
