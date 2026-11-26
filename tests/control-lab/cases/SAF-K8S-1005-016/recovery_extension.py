"""Scratch-only native reconciliation witness for SAF-K8S-1005-016.

This is an inert local Deployment marker, not an AI model or deployed recovery.
"""
import copy
import hashlib
import json
from pathlib import Path
import time


NAME = "saf1005016-recovery-target"
SELECTOR = "saf-lab.example/recovery-target=true"


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _marker_config(name, marker):
    return {
        "apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
        "metadata": {"name": name, "namespace": "saf-test",
                     "labels": {"saf-lab.example/control": "SAF-K8S-1005-016",
                                "saf-lab.example/fixture": "true"}},
        "data": {"marker.json": json.dumps(marker, sort_keys=True)},
    }


def _deployment(marker_name, marker, *, decision_id, action, python_image):
    approved_sha = marker["artifact_sha256"]
    approved_ref = marker["artifact_ref"]
    template_annotations = {
        "saf-lab.example/recovery-action": action,
        "saf-lab.example/decision-id": decision_id,
        "saf-lab.example/artifact-ref": approved_ref,
        "saf-lab.example/artifact-sha256": approved_sha,
    }
    readiness = (
        "import json,pathlib; m=json.loads(pathlib.Path('/fixture/marker.json').read_text()); "
        f"assert m.get('state') == 'healthy' and m.get('artifact_ref') == {json.dumps(approved_ref)} "
        f"and m.get('artifact_sha256') == {json.dumps(approved_sha)}"
    )
    runner = (
        "import json,pathlib,time\n"
        "m=json.loads(pathlib.Path('/fixture/marker.json').read_text())\n"
        "print(json.dumps({'state':'ready','marker':m},sort_keys=True),flush=True)\n"
        "while True:\n    time.sleep(3600)\n"
    )
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": NAME, "namespace": "saf-test",
                     "labels": {"saf-lab.example/control": "SAF-K8S-1005-016",
                                "saf-lab.example/fixture": "true"},
                     "annotations": template_annotations},
        "spec": {
            "replicas": 1, "revisionHistoryLimit": 1,
            "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": {"app": NAME}},
            "template": {
                "metadata": {"labels": {"app": NAME, "saf-lab.example/recovery-target": "true"},
                             "annotations": template_annotations},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{
                        "name": "inert-marker", "image": python_image,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "-c", runner],
                        "readinessProbe": {"exec": {"command": ["python", "-c", readiness]},
                                           "periodSeconds": 2, "timeoutSeconds": 2,
                                           "failureThreshold": 4},
                        "securityContext": {"readOnlyRootFilesystem": True,
                                             "allowPrivilegeEscalation": False,
                                             "capabilities": {"drop": ["ALL"]}},
                        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                      "limits": {"cpu": "100m", "memory": "64Mi"}},
                        "volumeMounts": [{"name": "marker", "mountPath": "/fixture",
                                          "readOnly": True}],
                    }],
                    "volumes": [{"name": "marker", "configMap": {"name": marker_name}}],
                },
            },
        },
    }


def _wait_ready(lab):
    lab.kubectl("rollout", "status", f"deployment/{NAME}", "--timeout=90s", timeout=100)
    deployment = json.loads(lab.kubectl("get", "deployment", NAME, "-o", "json").stdout)
    pods = json.loads(lab.kubectl("get", "pods", "-l", SELECTOR, "-o", "json").stdout)["items"]
    active_pods = [pod for pod in pods if not pod["metadata"].get("deletionTimestamp")]
    if len(active_pods) != 1:
        lab.block(f"Expected one active recovery fixture Pod; saw {len(active_pods)}")
    pods = active_pods
    pod = pods[0]
    ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                for c in pod.get("status", {}).get("conditions", []))
    if not ready:
        lab.block("The inert recovery target Pod did not become Ready")
    log = lab.kubectl("logs", pod["metadata"]["name"]).stdout.strip().splitlines()
    try:
        marker_record = json.loads(log[-1])
    except (IndexError, json.JSONDecodeError) as error:
        lab.block(f"The recovery target did not emit its inert marker: {error}")
    status = deployment.get("status", {})
    snapshot = {
        "uid": deployment["metadata"]["uid"],
        "generation": deployment["metadata"]["generation"],
        "spec": copy.deepcopy(deployment["spec"]),
        "status": {key: status.get(key) for key in
                   ("observedGeneration", "replicas", "updatedReplicas", "readyReplicas", "availableReplicas")},
        "pod": {"name": pod["metadata"]["name"], "uid": pod["metadata"]["uid"],
                "ready": ready, "marker_record": marker_record},
    }
    return snapshot


def _run_job(lab, name, config_name, python_image):
    job = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": "saf-test",
                     "labels": {"saf-lab.example/control": "SAF-K8S-1005-016",
                                "saf-lab.example/fixture": "true"}},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 75,
                 "template": {"metadata": {"labels": {"saf-lab.example/job": name}},
                              "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                       "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                            "seccompProfile": {"type": "RuntimeDefault"}},
                                       "containers": [{"name": "review", "image": python_image,
                                                       "imagePullPolicy": "IfNotPresent",
                                                       "command": ["python", "/fixture/review_workflow.py", "recovery"],
                                                       "securityContext": {"readOnlyRootFilesystem": True,
                                                                           "allowPrivilegeEscalation": False,
                                                                           "capabilities": {"drop": ["ALL"]}},
                                                       "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                                     "limits": {"cpu": "100m", "memory": "64Mi"}},
                                                       "volumeMounts": [{"name": "decision", "mountPath": "/fixture",
                                                                         "readOnly": True}]}],
                                       "volumes": [{"name": "decision", "configMap": {"name": config_name}}]}}},
    }
    lab.create(job)
    deadline = time.monotonic() + 95
    terminal = None
    while time.monotonic() < deadline:
        observed = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        terminal = next((c["type"] for c in observed.get("status", {}).get("conditions", [])
                         if c.get("status") == "True" and c.get("type") in {"Complete", "Failed"}), None)
        if terminal:
            break
        time.sleep(1)
    if terminal is None:
        lab.block("The approved rollback decision validator did not reach a terminal state")
    pods = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={name}", "-o", "json").stdout)["items"]
    if len(pods) != 1:
        lab.block("Expected exactly one rollback decision review Pod")
    container = pods[0].get("status", {}).get("containerStatuses", [])
    terminated = container[0].get("state", {}).get("terminated") if container else None
    output = lab.kubectl("logs", f"job/{name}").stdout.strip()
    try:
        outcome = json.loads(output)
    except json.JSONDecodeError as error:
        lab.block(f"The rollback decision validator did not emit JSON: {error}")
    return {"condition": terminal, "exit_code": terminated.get("exitCode") if terminated else None,
            "outcome": outcome}


def _decision_config(name, decision, target, trusted, validator):
    return {
        "apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
        "metadata": {"name": name, "namespace": "saf-test",
                     "labels": {"saf-lab.example/control": "SAF-K8S-1005-016",
                                "saf-lab.example/fixture": "true"}},
        "data": {"decision.json": json.dumps(decision, sort_keys=True),
                 "rollback-target.json": json.dumps(target, sort_keys=True),
                 "trusted-evidence.json": json.dumps({"fixture_only": True,
                                                       "references": trusted["references"]}, sort_keys=True),
                 **trusted["sources"],
                 "review_workflow.py": validator},
    }


def _approved_rollback_decision(target, trusted):
    decision_path = Path(__file__).parent / "fixtures" / "decision-record.json"
    rollback = json.loads(decision_path.read_text(encoding="utf-8"))
    rollback["recovery_action"] = "rollback"
    rollback["reason"] = "Approve the exact, synthetic fixture revision for this rehearsal."
    rollback["rollback_target"]["sha256"] = target["sha256"]
    for ref in rollback["evidence_refs"]:
        ref["sha256"] = trusted["references"][ref["ref"]]["sha256"]
    return rollback


def run_extension(lab, target, trusted, validator, python_image):
    raw = {"notice": "Inert local Deployment only; no model/application artifact or external endpoint.",
           "baseline": None, "denied": None, "approved_decision": None, "after_rollback": None}
    baseline_bytes = b"fixture baseline marker; no model or app artifact\n"
    baseline = {"state": "healthy", "artifact_ref": "urn:example:saf:fixture:baseline",
                "artifact_sha256": _hash(baseline_bytes), "fixture_only": True}
    expected = {"state": "healthy", "artifact_ref": target["artifact_ref"],
                "artifact_sha256": target["sha256"], "fixture_only": True}
    lab.create(_marker_config("saf1005016-marker-baseline", baseline))
    lab.create(_deployment("saf1005016-marker-baseline", baseline,
                           decision_id="urn:example:saf:decision:baseline", action="baseline",
                           python_image=python_image))
    before = _wait_ready(lab)
    raw["baseline"] = before
    baseline_ok = (bool(before["uid"]) and bool(before["pod"]["uid"])
                   and before["status"].get("observedGeneration") == before["generation"]
                   and before["status"].get("readyReplicas") == 1
                   and before["pod"]["marker_record"].get("marker") == baseline)
    lab.check("positive", "The owned baseline Deployment is Ready with its exact inert baseline marker",
              baseline_ok, {"deployment_uid_observed": bool(before["uid"]), "generation": before["generation"],
                            "status": before["status"], "pod_uid_observed": bool(before["pod"]["uid"]),
                            "marker": before["pod"]["marker_record"]})

    rollback = _approved_rollback_decision(target, trusted)
    denied_record = copy.deepcopy(rollback)
    denied_record["rollback_target"]["sha256"] = baseline["artifact_sha256"]
    denied_name = "saf1005016-denied-execution-record"
    lab.create(_decision_config(denied_name, denied_record, target, trusted, validator))
    denied = _run_job(lab, "saf1005016-denied-action-review", denied_name, python_image)
    after_denial = _wait_ready(lab)
    raw["denied"] = {"decision_result": denied, "target_after": after_denial}
    denial_unchanged = (
        denied["condition"] == "Failed" and denied["exit_code"] == 1
        and "rollback_target_untrusted_or_mismatched" in denied["outcome"].get("errors", [])
        and after_denial["uid"] == before["uid"]
        and after_denial["generation"] == before["generation"]
        and after_denial["spec"] == before["spec"]
        and after_denial["pod"]["uid"] == before["pod"]["uid"]
        and after_denial["pod"]["marker_record"] == before["pod"]["marker_record"]
    )
    lab.check("green", "A reviewed wrong-target decision is denied and leaves the native target unchanged",
              denial_unchanged, {"denial": denied["outcome"], "same_deployment_uid": after_denial["uid"] == before["uid"],
                                 "same_generation": after_denial["generation"] == before["generation"],
                                 "same_pod_uid": after_denial["pod"]["uid"] == before["pod"]["uid"],
                                 "same_marker": after_denial["pod"]["marker_record"] == before["pod"]["marker_record"]})

    approved_name = "saf1005016-approved-execution-record"
    execution_cm = _decision_config(approved_name, rollback, target, trusted, validator)
    saved = lab.create(execution_cm)
    readback = json.loads(lab.kubectl("get", "configmap", approved_name, "-o", "json").stdout)
    exact_record = (readback.get("immutable") is True
                    and readback.get("metadata", {}).get("uid") == saved["metadata"]["uid"]
                    and readback.get("data") == execution_cm["data"])
    lab.check("positive", "The exact approved rollback record and fixture evidence are immutable before execution",
              exact_record, {"immutable": readback.get("immutable"),
                             "uid_matches_create": readback.get("metadata", {}).get("uid") == saved["metadata"]["uid"],
                             "exact_data_readback": readback.get("data") == execution_cm["data"]})
    outcome = _run_job(lab, "saf1005016-rollback-action-review", approved_name, python_image)
    raw["approved_decision"] = {"uid": saved["metadata"]["uid"], "decision_id": rollback["decision_id"],
                                "record_sha256": _hash(execution_cm["data"]["decision.json"].encode()),
                                "target_ref": rollback["rollback_target"]["artifact_ref"],
                                "target_sha256": rollback["rollback_target"]["sha256"],
                                "validator": outcome}
    approved = (outcome["condition"] == "Complete" and outcome["exit_code"] == 0
                and outcome["outcome"].get("decision") == "approved_fixture_only_conditional"
                and outcome["outcome"].get("recovery_action") == "rollback"
                and outcome["outcome"].get("rollback_target") == target["artifact_ref"])
    lab.check("positive", "The immutable reviewed rollback record authorizes only its exact fixture target",
              approved, {"decision_id": rollback["decision_id"], "target": target["artifact_ref"],
                         "sha256": target["sha256"], "validator": outcome})

    marker_config = "saf1005016-marker-approved-rollback"
    lab.create(_marker_config(marker_config, expected))
    deployment = _deployment(marker_config, expected, decision_id=rollback["decision_id"],
                             action="rollback", python_image=python_image)
    lab.kubectl("apply", "-f", "-", payload=json.dumps(deployment))
    after = _wait_ready(lab)
    raw["after_rollback"] = after
    status = after["status"]
    after_ok = (
        after["uid"] == before["uid"]
        and after["generation"] > before["generation"]
        and status.get("observedGeneration") == after["generation"]
        and status.get("updatedReplicas") == 1 and status.get("readyReplicas") == 1
        and status.get("availableReplicas") == 1
        and after["pod"]["uid"] != before["pod"]["uid"]
        and after["pod"]["marker_record"].get("marker") == expected
        and after["pod"]["marker_record"].get("state") == "ready"
        and after["spec"]["template"]["metadata"]["annotations"].get("saf-lab.example/decision-id")
        == rollback["decision_id"]
    )
    lab.check("positive", "The approved rollback reconciles to one Ready Pod serving the exact target marker",
              after_ok, {"generation_before": before["generation"], "generation_after": after["generation"],
                         "status": status, "deployment_uid_preserved": after["uid"] == before["uid"],
                         "pod_uid_replaced": after["pod"]["uid"] != before["pod"]["uid"],
                         "marker": after["pod"]["marker_record"],
                         "decision_id": rollback["decision_id"]})

    (lab.evidence / "recovery-reconciliation.raw.json").write_text(
        json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")
