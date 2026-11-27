"""Exercise OCTAVE risk-traceability review as native Kubernetes Jobs."""
import json
from pathlib import Path
import time

from fixtures import container

HERE = Path(__file__).resolve().parent
CONFIG = "octave-fixtures"
AS_OF = "2026-11-22"
PYTHON = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SCOPE = (
    "Kubernetes v1.36.1 Kind runs independent native review Jobs over synthetic OCTAVE worksheets. "
    "The gate checks Phase 1 asset/impact/threat profiles, Phase 2 supporting infrastructure and "
    "vulnerability evidence, and Phase 3 tolerance-linked treatment and review cadence. It proves "
    "record completeness and stable decisions only. The scratch extension also binds a review to a "
    "case-owned ConfigMap topology snapshot and tests an annual due-date boundary with a documented "
    "Feb-29-to-Feb-28 policy. Organizational risk scoring, stakeholder judgment, evidence truth, "
    "implementation, cadence approval, and actual risk reduction require separate evidence."
)


def run_job(lab, items, name, worksheet, enforce=True):
    command = (["python", "/fixture/review_gate.py", f"/fixture/{worksheet}.json", "--as-of", AS_OF] if enforce else
               ["python", "-c", "import json,sys; json.load(open(sys.argv[1])); print('{\"status\":\"accepted-before-gate\",\"errors\":[]}')", f"/fixture/{worksheet}.json"])
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 65,
          "template": {"metadata": {"labels": {"saf.review": name}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [container("review", image=PYTHON, command=command,
              volumeMounts=[{"name": "fixture", "mountPath": "/fixture", "readOnly": True}])],
            "volumes": [{"name": "fixture", "configMap": {"name": CONFIG, "items": items}}]}}}})
    return collect_job(lab, name)


def collect_job(lab, name):
    """Collect a bounded Job result and bind the selected Pod to its controller UID."""
    deadline = time.monotonic() + 70
    while time.monotonic() < deadline:
        state = json.loads(lab.kubectl("get", "job", name, "-o", "json", timeout=15).stdout)
        settled = [c for c in state.get("status", {}).get("conditions", [])
                   if c.get("status") == "True" and c.get("type") in {"Failed", "Complete"}]
        if settled:
            break
        time.sleep(1)
    else:
        lab.block(f"Review Job {name} did not reach a terminal condition")
    podlist = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={name}", "-o", "json", timeout=15).stdout)
    pod, = podlist["items"]
    controller = next((owner for owner in pod.get("metadata", {}).get("ownerReferences", [])
                       if owner.get("controller") is True and owner.get("kind") == "Job"), None)
    owner_matches = bool(controller and controller.get("name") == name and controller.get("uid") == state["metadata"]["uid"])
    if not owner_matches:
        lab.block(f"Selected Pod for {name} is not owned by the observed Job UID")
    terminated = pod["status"]["containerStatuses"][0]["state"]["terminated"]
    logs = lab.kubectl("logs", f"job/{name}", timeout=15).stdout
    if not logs.strip():
        lab.block(f"Review Job {name} returned no decision")
    return {"job": name, "job_uid": state["metadata"]["uid"], "pod_uid": pod["metadata"]["uid"],
            "pod_owner_uid_matches_job": owner_matches, "controller": settled[0]["type"],
            "exit_code": terminated["exitCode"], "review": json.loads(logs)}



def run(lab):
    names = ("incomplete", "complete")
    data = {"review_gate.py": (HERE / "review_gate.py").read_text()}
    data.update({f"{n}.json": (HERE / "fixtures" / f"{n}.json").read_text() for n in names})
    evidence = HERE / "fixtures" / "evidence"
    data.update({source.name: source.read_text() for source in sorted(evidence.glob("*.md"))})
    items = [{"key": key, "path": f"evidence/{key}" if key.endswith(".md") else key} for key in data]
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CONFIG}, "data": data})
    disabled = run_job(lab, items, "octave-no-gate", "incomplete", False)
    missing = run_job(lab, items, "octave-incomplete", "incomplete")
    complete = run_job(lab, items, "octave-complete", "complete")
    raw = {"as_of": AS_OF, "disabled": disabled, "incomplete": missing, "complete": complete}
    (lab.evidence / "octave-job-observations.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    lab.check("red", "Disabled review accepts a structurally readable incomplete worksheet",
        (disabled["controller"], disabled["exit_code"], disabled["review"]["status"]) == ("Complete", 0, "accepted-before-gate"),
        {"controller": disabled["controller"], "exit_code": disabled["exit_code"]})
    errors = missing["review"].get("errors", [])
    lab.check("green", "Native Job rejects gaps in impact-to-treatment traceability and review cadence",
        missing["controller"] == "Failed" and missing["exit_code"] == 1 and
        "phase1-impact-missing:model-core" in errors and "phase2-infrastructure-link-missing:model-core" in errors and
        "phase3-tolerance-missing:model-core" in errors and "phase3-treatment-missing:model-core" in errors and
        "review-cadence-missing" in errors, {"errors": errors})
    lab.check("positive", "Complete synthetic OCTAVE worksheet passes with deterministic decision and independent evidence fields",
        complete["controller"] == "Complete" and complete["exit_code"] == 0 and complete["review"] == {"status": "pass", "errors": []},
        {"status": complete["review"]["status"], "assets": 4})
    run_change_review(lab)


def topology_state(cm):
    import hashlib
    topology = cm.get("data", {}).get("topology.json", "")
    return {
        "name": cm["metadata"]["name"],
        "namespace": cm["metadata"].get("namespace", ""),
        "uid": cm["metadata"]["uid"],
        "resource_version": cm["metadata"]["resourceVersion"],
        "revision": cm.get("metadata", {}).get("annotations", {}).get("saf.example/revision", ""),
        "scoped_annotations": {key: value for key, value in cm.get("metadata", {}).get("annotations", {}).items()
                               if key in {"saf.example/revision", "saf.example/observation"}},
        "topology_json": topology,
        "topology_sha256": hashlib.sha256(topology.encode()).hexdigest(),
    }


def lifecycle_job(lab, name, worksheet, state, as_of, cadence_cases=False):
    """Run one additive review through an isolated native Job and read-only ConfigMap."""
    config_name = f"{name}-input"
    evidence = HERE / "fixtures" / "evidence"
    payload = {
        "lifecycle_gate.py": (HERE / "lifecycle_gate.py").read_text(),
        "review_gate.py": (HERE / "review_gate.py").read_text(),
        "worksheet.json": json.dumps(worksheet, sort_keys=True),
        "change-state.json": json.dumps(state, sort_keys=True),
    }
    if cadence_cases:
        payload["cadence-cases.json"] = (HERE / "fixtures" / "cadence-cases.json").read_text()
    payload.update({f"evidence/{p.name}": p.read_text() for p in sorted(evidence.glob("*.md"))})
    data = {key.replace("evidence/", "evidence_"): value for key, value in payload.items()}
    items = [{"key": key, "path": path} for key, path in ((key.replace("evidence/", "evidence_"), key) for key in payload)]
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": config_name},
                "immutable": True, "data": data})
    command = (["python", "/fixture/lifecycle_gate.py", "--cadence-cases", "/fixture/cadence-cases.json"] if cadence_cases else
               ["python", "/fixture/lifecycle_gate.py", "/fixture/worksheet.json", "/fixture/change-state.json", "--as-of", as_of])
    job = f"{name}"
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": job},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 65,
          "template": {"metadata": {"labels": {"saf.review": job}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [container("review", image=PYTHON, command=command,
              volumeMounts=[{"name": "fixture", "mountPath": "/fixture", "readOnly": True}])],
            "volumes": [{"name": "fixture", "configMap": {"name": config_name, "items": items}}]}}}})
    return collect_job(lab, job)


def run_change_review(lab):
    topology_name = "octave-topology"
    topology_v1 = json.dumps({"model_endpoint": "inference-a", "gpu_pool": "pool-a", "revision": 1}, sort_keys=True)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": topology_name,
        "labels": {"saf.example/fixture": "octave-change-review"},
        "annotations": {"saf.example/revision": "1"}}, "data": {"topology.json": topology_v1}})
    before_cm = json.loads(lab.kubectl("get", "configmap", topology_name, "-o", "json", timeout=15).stdout)
    before = topology_state(before_cm)
    worksheet = json.loads((HERE / "fixtures" / "complete.json").read_text())
    worksheet["review_cadence"].update({"last_review": "2026-11-22", "annual_due": "2027-11-22", "reviewed_change": before})
    prior = lifecycle_job(lab, "octave-review-before-change", worksheet, before, "2026-11-22")

    # Metadata-only change must not stale the assessment even though API resourceVersion advances.
    metadata_patch = {"metadata": {"annotations": {"saf.example/observation": "metadata-only"}}}
    lab.kubectl("patch", "configmap", topology_name, "--type=merge", "-p", json.dumps(metadata_patch, sort_keys=True), timeout=15)
    metadata_cm = json.loads(lab.kubectl("get", "configmap", topology_name, "-o", "json", timeout=15).stdout)
    metadata_only = topology_state(metadata_cm)
    metadata_annotation_changed = ("saf.example/observation" not in before["scoped_annotations"]
                                   and metadata_only["scoped_annotations"].get("saf.example/observation") == "metadata-only")
    same_governed_input = (before["uid"] == metadata_only["uid"] and before["revision"] == metadata_only["revision"]
                           and before["topology_sha256"] == metadata_only["topology_sha256"])
    metadata_review = lifecycle_job(lab, "octave-review-after-metadata-only", worksheet, metadata_only, "2026-11-22")

    topology_v2 = json.dumps({"model_endpoint": "inference-b", "gpu_pool": "pool-b", "revision": 2}, sort_keys=True)
    major_patch = {"metadata": {"annotations": {"saf.example/revision": "2"}}, "data": {"topology.json": topology_v2}}
    lab.kubectl("patch", "configmap", topology_name, "--type=merge", "-p", json.dumps(major_patch, sort_keys=True), timeout=15)
    after_cm = json.loads(lab.kubectl("get", "configmap", topology_name, "-o", "json", timeout=15).stdout)
    after = topology_state(after_cm)
    major_change = (metadata_only["uid"] == after["uid"] and metadata_only["resource_version"] != after["resource_version"]
                    and metadata_only["revision"] != after["revision"]
                    and metadata_only["topology_sha256"] != after["topology_sha256"])
    stale = lifecycle_job(lab, "octave-stale-review-after-change", worksheet, after, "2026-11-23")
    refreshed_doc = json.loads(json.dumps(worksheet))
    refreshed_doc["review_cadence"].update({"last_review": "2026-11-23", "annual_due": "2027-11-23", "reviewed_change": after})
    refreshed = lifecycle_job(lab, "octave-refreshed-review-after-change", refreshed_doc, after, "2026-11-23")
    cadence_result = lifecycle_job(lab, "octave-cadence-boundaries", refreshed_doc, after, "2026-11-23", cadence_cases=True)
    import hashlib
    scoped_states = {"before": before, "metadata_only": metadata_only, "after_major_change": after}
    digest_recomputed = {stage: hashlib.sha256(state["topology_json"].encode()).hexdigest() == state["topology_sha256"]
                         for stage, state in scoped_states.items()}
    raw = {
        "scoped_configmap_states": scoped_states,
        "topology_digest_recomputed_from_raw_data": digest_recomputed,
        "metadata_only_resource_version_advanced": before["resource_version"] != metadata_only["resource_version"],
        "metadata_only_annotation_changed": metadata_annotation_changed,
        "metadata_only_governed_inputs_equal": same_governed_input,
        "major_change_governed_inputs_changed": major_change,
        "prior_review_before_change": prior,
        "review_after_metadata_only_change": metadata_review,
        "stale_review_after_major_change": stale,
        "refreshed_review_after_major_change": refreshed,
        "cadence_boundaries": cadence_result,
    }
    (lab.evidence / "octave-change-review-observations.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    lab.check("positive", "Previously reviewed worksheet matches the captured topology before change",
        prior["controller"] == "Complete" and prior["exit_code"] == 0 and prior["review"]["status"] == "pass",
        {"status": prior["review"]["status"], "pod_owner_uid_matches_job": prior["pod_owner_uid_matches_job"]})
    lab.check("positive", "Metadata-only resourceVersion change leaves the governed review valid",
        before["resource_version"] != metadata_only["resource_version"] and metadata_annotation_changed and same_governed_input and
        all(digest_recomputed.values()) and
        metadata_review["controller"] == "Complete" and metadata_review["exit_code"] == 0 and
        metadata_review["review"]["status"] == "pass",
        {"resource_version_advanced": before["resource_version"] != metadata_only["resource_version"],
         "metadata_annotation_changed": metadata_annotation_changed,
         "governed_inputs_equal": same_governed_input, "status": metadata_review["review"]["status"]})
    lab.check("red", "Major topology revision invalidates the prior review binding",
        major_change and all(digest_recomputed.values()) and stale["controller"] == "Failed" and stale["exit_code"] == 1 and
        stale["review"] == {"status": "fail", "errors": ["major-change-review-stale"]},
        {"governed_inputs_changed": major_change, "errors": stale["review"].get("errors", [])})
    lab.check("positive", "Refreshed review bound to the changed ConfigMap revision passes",
        refreshed["controller"] == "Complete" and refreshed["exit_code"] == 0 and refreshed["review"] == {"status": "pass", "errors": []},
        {"status": refreshed["review"]["status"], "pod_owner_uid_matches_job": refreshed["pod_owner_uid_matches_job"]})
    cadence_observed = cadence_result["review"]
    lab.check("positive", "Annual cadence accepts the boundary date and applies Feb 29 to Feb 28",
        cadence_result["controller"] == "Complete" and cadence_result["exit_code"] == 0 and
        cadence_observed.get("ordinary_due_boundary", {}).get("status") == "pass" and
        cadence_observed.get("leap_review_feb28_policy_boundary", {}).get("status") == "pass",
        {"ordinary_due_boundary": cadence_observed.get("ordinary_due_boundary", {}).get("status"),
         "leap_review_feb28_policy_boundary": cadence_observed.get("leap_review_feb28_policy_boundary", {}).get("status")})
    lab.check("red", "Annual cadence rejects overdue and beyond-anniversary due dates",
        cadence_result["controller"] == "Complete" and cadence_result["exit_code"] == 0 and
        cadence_observed.get("ordinary_one_day_overdue", {}).get("errors") == ["review-overdue"] and
        cadence_observed.get("ordinary_due_too_distant", {}).get("errors") == ["annual-due-after-anniversary"] and
        cadence_observed.get("leap_review_due_too_distant", {}).get("errors") == ["annual-due-after-anniversary"],
        {"ordinary_one_day_overdue": cadence_observed.get("ordinary_one_day_overdue", {}).get("errors"),
         "ordinary_due_too_distant": cadence_observed.get("ordinary_due_too_distant", {}).get("errors"),
         "leap_review_due_too_distant": cadence_observed.get("leap_review_due_too_distant", {}).get("errors")})
    run_phase3_traceability(lab)


def phase3_trace_job(lab, name, worksheet):
    """Run one immutable synthetic Phase 3 traceability counterfactual."""
    import hashlib

    config_name = f"{name}-input"
    evidence = HERE / "fixtures" / "evidence"
    payload = {
        "phase3_trace_gate.py": (HERE / "phase3_trace_gate.py").read_text(),
        "review_gate.py": (HERE / "review_gate.py").read_text(),
        "worksheet.json": json.dumps(worksheet, sort_keys=True),
    }
    payload.update({f"evidence/{p.name}": p.read_text() for p in sorted(evidence.glob("*.md"))})
    data = {key.replace("evidence/", "evidence_"): value for key, value in payload.items()}
    items = [{"key": key.replace("evidence/", "evidence_"), "path": key} for key in payload]
    submitted = lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": config_name},
                            "immutable": True, "data": data})
    config_uid = submitted.get("metadata", {}).get("uid")
    if not config_uid or submitted.get("immutable") is not True or submitted.get("data") != data:
        lab.block("The Phase 3 worksheet was not preserved in its exact immutable API input")
    command = ["python", "/fixture/phase3_trace_gate.py", "/fixture/worksheet.json",
               "--evidence-root", "/fixture", "--as-of", AS_OF]
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 65,
          "template": {"metadata": {"labels": {"saf.review": name}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [container("review", image=PYTHON, command=command,
              volumeMounts=[{"name": "fixture", "mountPath": "/fixture", "readOnly": True}])],
            "volumes": [{"name": "fixture", "configMap": {"name": config_name, "items": items}}]}}}})
    result = collect_job(lab, name)
    result["input_configmap_uid"] = config_uid
    result["input_sha256"] = hashlib.sha256(submitted["data"]["worksheet.json"].encode()).hexdigest()
    return result


def run_phase3_traceability(lab):
    import copy

    complete = json.loads((HERE / "fixtures" / "complete.json").read_text())
    cases = json.loads((HERE / "fixtures" / "phase3-trace-cases.json").read_text())
    documents = {"positive": copy.deepcopy(complete)}
    for name, case in cases.items():
        doc = copy.deepcopy(complete)
        asset = next(asset for asset in doc["assets"] if asset["id"] == case["asset"])
        threat = asset["threats"][0]
        if name == "missing_evaluation":
            threat.pop("evaluation", None)
        elif name == "orphan_criterion":
            threat["evaluation"]["criterion_ref"] = "criterion-not-declared"
        elif name == "missing_outcome":
            threat["evaluation"].pop("outcome", None)
        elif name == "wrong_threat_reference":
            other_asset = next(item for item in doc["assets"] if item["id"] != case["asset"])
            asset["risk_treatment"]["threat_ref"] = other_asset["threats"][0]["scenario"]
        elif name == "misbound_priority":
            asset["risk_treatment"]["prioritization"]["outcome"] = "outcome-not-from-selected-evaluation"
        elif name == "duplicate_scenario":
            asset["threats"].append(copy.deepcopy(threat))
        documents[name] = doc

    observed = {name: phase3_trace_job(lab, f"octave-phase3-{name.replace('_', '-')}", doc)
                for name, doc in documents.items()}
    normalized = {name: {"controller": value["controller"], "exit_code": value["exit_code"],
                         "status": value["review"]["status"], "errors": value["review"].get("errors", [])}
                  for name, value in observed.items()}
    raw = {"observations": observed, "normalized": normalized, "counterfactual_definitions": cases,
           "synthetic_worksheets": documents}
    (lab.evidence / "octave-phase3-trace-observations.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    positive = observed["positive"]
    lab.check("positive", "Synthetic Phase 3 evaluation resolves declared criterion, exact threat and treatment",
        positive["controller"] == "Complete" and positive["exit_code"] == 0 and
        positive["review"] == {"status": "pass", "errors": []},
        {"status": positive["review"]["status"], "assets": 4,
         "pod_owner_uid_matches_job": positive["pod_owner_uid_matches_job"]})
    expected = {
        "missing_evaluation": ["phase3-priority-trace-invalid:model-core",
                               "phase3-risk-criterion-unresolved:model-core",
                               "phase3-treatment-threat-link-invalid:model-core"],
        "orphan_criterion": ["phase3-priority-trace-invalid:model-core",
                              "phase3-risk-criterion-unresolved:model-core",
                              "phase3-treatment-threat-link-invalid:model-core"],
        "missing_outcome": ["phase3-priority-trace-invalid:model-core",
                             "phase3-risk-outcome-invalid:model-core",
                             "phase3-treatment-threat-link-invalid:model-core"],
        "wrong_threat_reference": ["phase3-priority-trace-invalid:model-core",
                                   "phase3-treatment-threat-link-invalid:model-core"],
        "misbound_priority": ["phase3-priority-trace-invalid:model-core"],
        "duplicate_scenario": ["phase3-risk-scenario-ambiguous:model-core"],
    }
    for name, errors in expected.items():
        result = observed[name]
        lab.check("red", f"Phase 3 rejects {name.replace('_', ' ')} in a synthetic worksheet",
            result["controller"] == "Failed" and result["exit_code"] == 1 and
            result["review"] == {"status": "fail", "errors": errors},
            {"errors": result["review"].get("errors", []), "pod_owner_uid_matches_job": result["pod_owner_uid_matches_job"]})
