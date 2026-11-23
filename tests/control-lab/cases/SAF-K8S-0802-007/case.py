"""Correlate known workload inventory with inert device-report records."""

import json

SCOPE = "Live DaemonSet inventory reconciled with synthetic telemetry; no plugin, registration, device or socket is used."
NAME = "fixture-device-observer"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
RESOURCE = "fixture.example/owned-accelerator"


def inventory(lab):
    labels = {"app": NAME}
    ds = lab.create({"apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": {"name": NAME},
                     "spec": {"selector": {"matchLabels": labels}, "template": {"metadata": {"labels": labels}, "spec": {
                         "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [{"name": "fixture", "image": IMAGE,
                                         "command": ["python", "-c", "import time; time.sleep(160)"],
                                         "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                                       "limits": {"cpu": "100m", "memory": "40Mi"}},
                                         "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                                             "capabilities": {"drop": ["ALL"]}}}]}}}})
    lab.kubectl("rollout", "status", f"daemonset/{NAME}", "--timeout=60s", timeout=70)
    pods = json.loads(lab.kubectl("get", "pods", "-l", f"app={NAME}", "-o", "json").stdout)["items"]
    ready = [pod for pod in pods if any(c["type"] == "Ready" and c["status"] == "True"
                                      for c in pod.get("status", {}).get("conditions", []))]
    if len(ready) != 1:
        lab.block("Expected exactly one ready Pod from the owned inventory fixture")
    pod = ready[0]
    owners = [owner for owner in pod["metadata"]["ownerReferences"] if owner.get("controller") is True]
    if len(owners) != 1 or owners[0]["uid"] != ds["metadata"]["uid"] or pod["spec"]["containers"][0]["image"] != IMAGE:
        lab.block("The runtime inventory does not match the approved owned DaemonSet")
    return {"node": pod["spec"]["nodeName"], "origin": owners[0]["uid"], "image": IMAGE}


def reconcile(report, deployed):
    if any(key not in report for key in ("origin", "node", "image", "resource", "devices", "reported_allocatable")):
        return "incomplete"
    if any(report[key] != deployed[key] for key in ("origin", "node", "image")):
        return "deployment-mismatch"
    if report["resource"] != RESOURCE:
        return "resource-mismatch"
    devices = report["devices"]
    if len({device["id"] for device in devices}) != len(devices):
        return "duplicate-device"
    if sum(device["status"] == "healthy" for device in devices) != report["reported_allocatable"]:
        return "health-mismatch"
    return "consistent-fixture"


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    actual = inventory(lab)
    approved = {**actual, "resource": RESOURCE, "devices": [{"id": "fixture-device", "status": "healthy"}],
                "reported_allocatable": 1}
    unmatched = dict(approved, origin="fixture-unlisted-origin")
    coarse = unmatched["resource"] == RESOURCE and unmatched["reported_allocatable"] == 1
    lab.check("red", "An expected resource and count alone accept a record with an unrelated origin",
              coarse, {"coarse_report_would_pass": coarse})

    cases = {
        "unlisted": unmatched,
        "missing": {key: value for key, value in approved.items() if key != "origin"},
        "changed_resource": dict(approved, resource="fixture.example/unapproved"),
        "duplicate": dict(approved, devices=approved["devices"] * 2),
        "different_health": dict(approved, devices=[{"id": "fixture-device", "status": "unhealthy"}]),
    }
    observed = {name: reconcile(row, actual) for name, row in cases.items()}
    expected = {"unlisted": "deployment-mismatch", "missing": "incomplete", "changed_resource": "resource-mismatch",
                "duplicate": "duplicate-device", "different_health": "health-mismatch"}
    lab.check("green", "Reconciliation distinguishes origin, completeness, resource, uniqueness and reported-health gaps",
              observed == expected, observed)
    matched = reconcile(approved, actual)
    lab.check("positive", "The expected synthetic report matches the live, approved workload inventory",
              matched == "consistent-fixture", {"approved_report": matched, "live_daemonset_ready": True})
    (lab.evidence / "plugin-inventory-observations.json").write_text(json.dumps({
        "live_daemonset_ready": True, "pinned_deployment_confirmed": True, "synthetic_report_results": observed,
        "approved_report": matched, "socket_or_plugin_tested": False}, indent=2) + "\n")
