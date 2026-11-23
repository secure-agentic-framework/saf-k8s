"""Generate fixture showback in a Job and verify scoped report publication."""

import hashlib
import json
from pathlib import Path

SCOPE = "Informational report generation and in-cluster availability with synthetic usage and amounts."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
TEAMS = {"saf-showback-amber": "amber", "saf-showback-indigo": "indigo", "saf-showback-unowned": None}
REPORT = "showback"


def config(lab, name, data, *, namespace="saf-test"):
    definition = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                  "immutable": True, "data": data}
    lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(definition))


def prepare(lab):
    lookup = {}
    for namespace, team in TEAMS.items():
        labels = {"saf.example/owner": team} if team else {}
        lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace, "labels": labels}})
        actual = json.loads(lab.kubectl("get", "namespace", namespace, "-o", "json").stdout)
        lookup[namespace] = actual["metadata"]["labels"].get("saf.example/owner")
    sample = {"owners": lookup, "period": ["2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"],
              "rate_revision": "illustrative-v1", "fixture_rates": {"synthetic-slot": "2.50"}, "shared_minor_units": 200,
              "usage": [{"id": "fixture-amber", "namespace": "saf-showback-amber", "hours": "2.0", "resource": "synthetic-slot"},
                        {"id": "fixture-indigo", "namespace": "saf-showback-indigo", "hours": "1.5", "resource": "synthetic-slot"},
                        {"id": "fixture-unowned", "namespace": "saf-showback-unowned", "hours": "0.5", "resource": "synthetic-slot"},
                        {"id": "fixture-unpriced", "namespace": "saf-showback-amber", "hours": "0.25", "resource": "unpriced-fixture"}]}
    raw = json.dumps(sample, sort_keys=True)
    config(lab, "showback-inputs", {"snapshot.json": raw, "report.py": Path(__file__).with_name("report.py").read_text()})
    return hashlib.sha256(raw.encode()).hexdigest()


def run_report(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "showback-processor"},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 60, "template": {"spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "input", "configMap": {"name": "showback-inputs"}}],
                    "containers": [{"name": "processor", "image": IMAGE, "command": ["python3", "/input/report.py"],
                                    "volumeMounts": [{"name": "input", "mountPath": "/input", "readOnly": True}],
                                    "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                  "limits": {"cpu": "100m", "memory": "64Mi"}},
                                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                        "capabilities": {"drop": ["ALL"]}}}],
                }}}})
    lab.kubectl("wait", "--for=condition=complete", "job/showback-processor", "--timeout=70s", timeout=80)
    return json.loads(lab.kubectl("logs", "job/showback-processor").stdout)


def create_reader(lab, namespace):
    subject = {"kind": "ServiceAccount", "name": "showback-reader", "namespace": namespace}
    for obj in (
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "showback-reader"}, "automountServiceAccountToken": False},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "showback-read"},
         "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [REPORT], "verbs": ["get"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "showback-read"},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "showback-read"}, "subjects": [subject]},
    ):
        lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(obj))


def get_report(lab, namespace, reader, name=REPORT):
    return lab.kubectl("-n", namespace, "--as", f"system:serviceaccount:{reader}:showback-reader", "get", "configmap",
                       name, "-o", "json", allow_failure=True)


def run(lab):
    input_hash = prepare(lab)
    report = run_report(lab)
    expected = {"amber": 500, "indigo": 375, "unallocated": 125}
    gap = report["priced_minor_units"] - report["naive_owner_only_minor_units"]
    lab.check("red", "Reporting only named owners omits priced unowned and shared fixture amounts",
              gap == 325, {"owner_only_omission_minor_units": gap})
    exact = (report["reported_minor_units"] == expected and report["shared_minor_units"] == 200
             and report["priced_minor_units"] == 1200 and report["unpriced_hours"] == "0.25"
             and report["exceptions"] == [{"id": "fixture-unowned", "reason": "missing-owner"},
                                           {"id": "fixture-unpriced", "reason": "missing-rate"}])
    lab.check("green", "The report retains shared, unallocated and unpriced inputs with explicit classifications",
              exact and report["input_sha256"] == input_hash,
              {"owner_minor_units": expected, "shared_minor_units": 200, "priced_total": 1200, "input_hash_matched": True})
    config(lab, "showback-consolidated", {"report.json": json.dumps(report, sort_keys=True)})
    owned = [(namespace, team) for namespace, team in TEAMS.items() if team]
    for namespace, team in owned:
        create_reader(lab, namespace)
        item = {key: report[key] for key in ("mode", "data_basis", "currency", "period", "rate_revision", "input_sha256")}
        item.update(owner=team, minor_units=report["reported_minor_units"][team])
        config(lab, REPORT, {"report.json": json.dumps(item, sort_keys=True)}, namespace=namespace)
    granted, refused = [], []
    for (namespace, team), (other, _) in zip(owned, reversed(owned)):
        allowed = get_report(lab, namespace, namespace)
        fields = json.loads(json.loads(allowed.stdout)["data"]["report.json"]) if allowed.returncode == 0 else {}
        granted.append(fields.get("owner") == team and fields.get("minor_units") == expected[team] and fields.get("mode") == "fixture-showback")
        denied = get_report(lab, other, namespace)
        refused.append(denied.returncode != 0 and "Forbidden" in denied.stderr)
    lab.check("positive", "The authorized readers can retrieve their informational report and receive cross-team denial",
              all(granted) and all(refused), {"own_reports_retrievable": all(granted), "cross_team_reads_denied": all(refused)})
    (lab.evidence / "showback-observations.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
