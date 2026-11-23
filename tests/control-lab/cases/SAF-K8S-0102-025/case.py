"""Verify bounded backup review alerts and observed local delivery."""

import json
from pathlib import Path

SCOPE = "Actual Kubernetes Jobs evaluate a synthetic backup event feed and deliver scoped notices to an in-cluster receiver."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
NAME = "fixture-backup-review"


def fixture_rows():
    routine = {"id": "routine", "source": "fixture-repository", "target": "fixture-backup-marker",
               "actor": "fixture-approved", "observed": 95}
    unexpected = {**routine, "id": "unexpected", "actor": "fixture-unexpected"}
    stale = {**routine, "id": "stale", "source": "fixture-offline-custody", "observed": 50}
    return [routine, unexpected, unexpected, stale]


def pod_spec(mode, *args):
    unit = {"name": "unit", "image": IMAGE, "command": ["python", "-B", "/fixture/fixture.py", mode, *args],
            "volumeMounts": [{"name": "config", "mountPath": "/fixture", "readOnly": True}],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                          "limits": {"cpu": "100m", "memory": "60Mi"}}}
    if mode == "receive":
        unit["readinessProbe"] = {"httpGet": {"path": "/", "port": 8080}, "periodSeconds": 1}
    return {"restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [unit], "volumes": [{"name": "config", "configMap": {"name": NAME}}]}


def evaluate(lab, mode):
    name = "fixture-review-" + mode
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "template": {"spec": pod_spec("evaluate", mode)}}})
    lab.kubectl("wait", "--for=condition=Complete", "job/" + name, "--timeout=70s", timeout=80)
    return json.loads(lab.kubectl("logs", "job/" + name).stdout)


def notices(lab):
    result = lab.kubectl("logs", "pod/" + NAME)
    return [json.loads(line) for line in result.stdout.splitlines()]


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME}, "immutable": True,
                "data": {"fixture.py": Path(__file__).with_name("fixture.py").read_text(),
                         "events.json": json.dumps(fixture_rows())}})
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": NAME, "labels": {"app": NAME}},
                "spec": pod_spec("receive")})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": NAME},
                "spec": {"selector": {"app": NAME}, "ports": [{"port": 8080, "targetPort": 8080}]}})
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + NAME, "--timeout=75s", timeout=85)
    baseline = evaluate(lab, "disabled")
    unreported = notices(lab) == []
    lab.check("red", "Evaluation without configured delivery leaves both review findings unreported",
              baseline == {"evaluated": 2, "delivered": 0} and unreported, baseline)

    configured = evaluate(lab, "deliver")
    observed = notices(lab)
    expected = [
        {"event": "unexpected", "kind": "review-access", "source": "fixture-repository", "owner": NAME},
        {"event": "fixture-offline-custody", "kind": "review-coverage", "source": "fixture-offline-custody", "owner": NAME},
    ]
    lab.check("green", "The reviewed route delivers separate notices for unusual access and a stale coverage source",
              configured == {"evaluated": 2, "delivered": 2} and observed == expected, {"notices": observed})
    permitted_quiet = all(row["event"] != "routine" for row in observed)
    deduplicated = sum(row["event"] == "unexpected" for row in observed) == 1
    lab.check("positive", "Routine access stays quiet and a replayed event creates one review notice",
              permitted_quiet and deduplicated, {"routine_quiet": permitted_quiet, "duplicate_suppressed": deduplicated})
    (lab.evidence / "backup-review-alert-observations.json").write_text(json.dumps({
        "notices": observed, "source_events_synthetic": True, "delivery_observed": True,
    }, indent=2) + "\n")
