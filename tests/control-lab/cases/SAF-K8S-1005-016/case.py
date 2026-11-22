"""Exercise native Kubernetes evidence records for a synthetic recovery decision."""
import hashlib
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-test"
OWNER = "urn:example:saf:role:security-operations-owner"
APPROVER = "urn:example:saf:role:security-operations-approver"
EVIDENCE_OWNER = "urn:example:saf:role:ai-engineering-reviewer"
TARGET_REF = "urn:example:saf:model-fixture:stable-000"
DECISION_FIXTURE = json.loads((FIXTURES / "decision-record.json").read_text(encoding="utf-8"))
VALIDATOR = r'''import hashlib, json, pathlib, sys
root = pathlib.Path("/fixture")
decision = json.loads((root / "decision.json").read_text())
trusted = json.loads((root / "trusted-evidence.json").read_text())
target = json.loads((root / "rollback-target.json").read_text())
mode = sys.argv[1]
if mode == "bypass":
    result = {"decision": "accepted_without_validation", "fixture_only": True,
              "record_id": decision.get("decision_id"), "validation_performed": False}
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0)

errors = []
if decision.get("fixture_only") is not True or decision.get("approval_status") != "approved":
    errors.append("decision_not_fixture_approved")
if decision.get("owner") != "urn:example:saf:role:security-operations-owner":
    errors.append("owner_missing_or_untrusted")
if decision.get("approver") != "urn:example:saf:role:security-operations-approver":
    errors.append("approver_missing_or_untrusted")
reason = decision.get("reason")
if not isinstance(reason, str) or len(reason.strip()) < 24:
    errors.append("reason_missing_or_too_short")

catalog = trusted.get("references", {})
source_files = {"integrity-result": "integrity-result.json", "reviewer-note": "reviewer-note.txt"}
refs = decision.get("evidence_refs")
expected_ids = {"integrity-result", "reviewer-note"}
seen = set()
refs_valid = isinstance(refs, list) and len(refs) == len(expected_ids)
if refs_valid:
    for ref in refs:
        if not isinstance(ref, dict):
            refs_valid = False
            continue
        ref_id = ref.get("ref")
        seen.add(ref_id)
        expected = catalog.get(ref_id)
        if (not expected or expected.get("fixture_only") is not True
                or ref.get("sha256") != expected.get("sha256")
                or expected.get("sha256") != hashlib.sha256((root / source_files[ref_id]).read_bytes()).hexdigest()):
            refs_valid = False
if not refs_valid or seen != expected_ids:
    errors.append("evidence_reference_untrusted_or_incomplete")

integrity = json.loads((root / "integrity-result.json").read_text())
target_hash = hashlib.sha256((root / "rollback-target.txt").read_bytes()).hexdigest()
if (trusted.get("fixture_only") is not True
        or integrity.get("fixture_only") is not True
        or integrity.get("integrity_status") != "passed"
        or integrity.get("artifact_ref") != target.get("artifact_ref")
        or integrity.get("artifact_sha256") != target.get("sha256")
        or target_hash != target.get("sha256")):
    errors.append("integrity_fixture_not_bound_to_target")

rollback = decision.get("rollback_target", {})
if (rollback.get("artifact_ref") != target.get("artifact_ref")
        or rollback.get("sha256") != target.get("sha256")
        or rollback.get("artifact_ref") != "urn:example:saf:model-fixture:stable-000"):
    errors.append("rollback_target_untrusted_or_mismatched")

unresolved = decision.get("unresolved_evidence")
unresolved_valid = isinstance(unresolved, list) and bool(unresolved)
if unresolved_valid:
    for item in unresolved:
        if not isinstance(item, dict):
            unresolved_valid = False
            break
        if (item.get("status") != "unresolved"
                or item.get("impact") != "nonblocking-for-fixture-only-review"
                or not item.get("item")
                or item.get("owner") != "urn:example:saf:role:ai-engineering-reviewer"
                or item.get("accepted_by") != "urn:example:saf:role:security-operations-approver"
                or not item.get("reason")
                or item.get("due") != "2099-01-15"):
            unresolved_valid = False
if not unresolved_valid:
    errors.append("unresolved_evidence_not_owned_and_explicitly_dispositioned")

if errors:
    print(json.dumps({"decision": "blocked", "errors": errors, "fixture_only": True,
                      "record_id": decision.get("decision_id"),
                      "unresolved_count": len(unresolved) if isinstance(unresolved, list) else None},
                     sort_keys=True))
    raise SystemExit(1)
print(json.dumps({"decision": "approved_fixture_only_conditional",
                  "fixture_only": True, "record_id": decision["decision_id"],
                  "rollback_target": target["artifact_ref"],
                  "unresolved_count": len(unresolved),
                  "unresolved_status": "explicitly_owned_nonblocking_for_fixture_only_review",
                  "production_readiness": "unverified"}, sort_keys=True))
'''
CONTROL_LABEL = "saf-lab.example/control"
CONTROL_ID = "SAF-K8S-1005-016"
SCOPE = (
    "One disposable Kind v1.36.1 cluster runs tokenless restricted Python Jobs against immutable, "
    "case-owned ConfigMaps containing synthetic JSON and inert text. A bypass Job accepts an "
    "invalid fictional rollback decision; enforced Jobs block invalid owner, reason, evidence-ref, "
    "rollback-target, and unresolved-evidence fields; a positive Job accepts a fixture-only "
    "conditional approval while retaining production validation as unverified. Jobs only emit "
    "decisions and never perform rollback, retraining, quarantine, deployment, or network calls. "
    "No model, real incident, secret, live feed, external target, or attack input is present. "
    "This tests the synthetic evidence workflow and Kubernetes observation path only; it does not "
    "establish authorization identity, fixture provenance beyond this case's files, integrity of "
    "evidence against a cluster administrator, AI-specific recovery criteria, production readiness, "
    "or organizational response coverage."
)


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture_bundle():
    target_bytes = (FIXTURES / "rollback-target.txt").read_bytes()
    target_sha = hashlib.sha256(target_bytes).hexdigest()
    integrity_bytes = (FIXTURES / "integrity-result.json").read_bytes()
    reviewer_bytes = (FIXTURES / "reviewer-note.txt").read_bytes()
    integrity_fixture = json.loads(integrity_bytes)
    target = {"artifact_ref": TARGET_REF, "sha256": target_sha, "fixture_only": True}
    trusted = {
        "fixture_only": True,
        "references": {
            "integrity-result": {"sha256": hashlib.sha256(integrity_bytes).hexdigest(),
                                 "fixture_only": True},
            "reviewer-note": {"sha256": hashlib.sha256(reviewer_bytes).hexdigest(),
                              "fixture_only": True},
        },
        "integrity_result": {
            "artifact_ref": integrity_fixture["artifact_ref"],
            "artifact_sha256": integrity_fixture["artifact_sha256"],
            "fixture_only": integrity_fixture["fixture_only"],
            "integrity_status": integrity_fixture["integrity_status"],
            "method": integrity_fixture["method"],
        },
    }
    trusted["sources"] = {
        "integrity-result.json": integrity_bytes.decode(), "reviewer-note.txt": reviewer_bytes.decode(),
        "rollback-target.txt": target_bytes.decode(),
    }
    if integrity_fixture.get("artifact_ref") != TARGET_REF or integrity_fixture.get("artifact_sha256") != target_sha:
        raise ValueError("Synthetic integrity fixture points outside the exact rollback target")
    return target, trusted, {
        "rollback-target.txt": target_sha,
        "integrity-result.json": hashlib.sha256(integrity_bytes).hexdigest(),
        "reviewer-note.txt": hashlib.sha256(reviewer_bytes).hexdigest(),
    }


def _decision_variants(trusted):
    base = json.loads(json.dumps(DECISION_FIXTURE))
    for ref in base["evidence_refs"]:
        ref["sha256"] = trusted["references"][ref["ref"]]["sha256"]
    base["rollback_target"]["sha256"] = trusted["integrity_result"]["artifact_sha256"]

    variants = {"positive": base}
    missing_owner = json.loads(json.dumps(base))
    missing_owner["owner"] = ""
    variants["missing-owner"] = missing_owner
    missing_reason = json.loads(json.dumps(base))
    missing_reason["reason"] = ""
    variants["missing-reason"] = missing_reason
    untrusted_reference = json.loads(json.dumps(base))
    untrusted_reference["evidence_refs"][0]["sha256"] = "0" * 64
    variants["untrusted-reference"] = untrusted_reference
    wrong_target = json.loads(json.dumps(base))
    wrong_target["rollback_target"]["artifact_ref"] = "urn:example:saf:model-fixture:unknown-999"
    variants["wrong-target"] = wrong_target
    unresolved = json.loads(json.dumps(base))
    unresolved["unresolved_evidence"][0]["owner"] = ""
    unresolved["unresolved_evidence"][0]["impact"] = "blocking"
    variants["unresolved-evidence"] = unresolved
    return variants


def _resource_name(suffix):
    return f"saf1005016-{suffix}"


def _configmap(name, decision, target, trusted):
    data = {
        "decision.json": json.dumps(decision, sort_keys=True),
        "rollback-target.json": json.dumps(target, sort_keys=True),
        "trusted-evidence.json": json.dumps({"fixture_only": True, "references": trusted["references"]},
                                             sort_keys=True),
        **trusted["sources"],
        "review_workflow.py": VALIDATOR,
    }
    return {"apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
            "metadata": {"name": name, "namespace": NAMESPACE,
                         "labels": {CONTROL_LABEL: CONTROL_ID, "saf-lab.example/fixture": "true"}},
            "data": data}


def _job(name, config_name, mode):
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {CONTROL_LABEL: CONTROL_ID, "saf-lab.example/fixture": "true"}},
        "spec": {
            "backoffLimit": 0, "activeDeadlineSeconds": 75,
            "template": {
                "metadata": {"labels": {"saf-lab.example/job": name}},
                "spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{
                        "name": "decision-review", "image": PYTHON_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "/fixture/review_workflow.py", mode],
                        "securityContext": {"readOnlyRootFilesystem": True,
                                             "allowPrivilegeEscalation": False,
                                             "capabilities": {"drop": ["ALL"]}},
                        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                      "limits": {"cpu": "100m", "memory": "64Mi"}},
                        "volumeMounts": [{"name": "decision", "mountPath": "/fixture",
                                          "readOnly": True}],
                    }],
                    "volumes": [{"name": "decision", "configMap": {"name": config_name}}],
                },
            },
        },
    }


def _observe_job(lab, job_name):
    deadline = time.monotonic() + 95
    job = None
    terminal = None
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", "job", job_name, "-o", "json").stdout)
        conditions = job.get("status", {}).get("conditions", [])
        terminal = next((row["type"] for row in conditions
                         if row.get("status") == "True"
                         and row.get("type") in {"Complete", "Failed"}), None)
        if terminal:
            break
        time.sleep(1)
    if terminal is None:
        lab.block(f"Case-owned Job {job_name} did not reach a terminal condition")
    pods = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={job_name}", "-o", "json").stdout)["items"]
    if len(pods) != 1:
        lab.block(f"Expected one case-owned Pod for {job_name}; observed {len(pods)}")
    pod = pods[0]
    statuses = pod.get("status", {}).get("containerStatuses", [])
    terminated = statuses[0].get("state", {}).get("terminated") if statuses else None
    if not terminated:
        lab.block(f"Case-owned Job {job_name} has no terminated container outcome")
    logs = lab.kubectl("logs", f"job/{job_name}").stdout
    try:
        outcome = json.loads(logs.strip())
    except json.JSONDecodeError as error:
        lab.block(f"Case-owned Job {job_name} did not emit its synthetic JSON outcome: {error}")
    return {"job": job_name, "job_uid": job["metadata"]["uid"],
            "job_condition": terminal, "pod_uid": pod["metadata"]["uid"],
            "exit_code": terminated["exitCode"], "raw_stdout": logs, "outcome": outcome}


def run(lab):
    target, trusted, fixture_digests = _fixture_bundle()
    variants = _decision_variants(trusted)
    observations = {
        "notice": "Synthetic fixture-only approval workflow; no secret, model, incident, feed, or target.",
        "node_image": NODE_IMAGE,
        "python_image": PYTHON_IMAGE,
        "fixture_sha256": fixture_digests,
        "node_kubelet_versions": [],
        "configmaps": {},
        "jobs": {},
    }
    variants["failed-integrity"] = json.loads(json.dumps(variants["positive"]))
    failed = json.loads(json.dumps(trusted))
    outcome = json.loads(failed["sources"]["integrity-result.json"])
    outcome["integrity_status"] = "failed"
    updated = json.dumps(outcome, sort_keys=True)
    failed["sources"]["integrity-result.json"] = updated
    digest = hashlib.sha256(updated.encode()).hexdigest()
    failed["references"]["integrity-result"]["sha256"] = digest
    next(ref for ref in variants["failed-integrity"]["evidence_refs"]
         if ref["ref"] == "integrity-result")["sha256"] = digest
    results = {}
    for variant, decision in variants.items():
        config_name = _resource_name(f"{variant}-record")
        bundle = failed if variant == "failed-integrity" else trusted
        resource = _configmap(config_name, decision, target, bundle)
        created = lab.create(resource)
        readback = json.loads(lab.kubectl("get", "configmap", config_name, "-o", "json").stdout)
        exact_readback = (readback.get("immutable") is True
                          and readback.get("metadata", {}).get("uid") == created["metadata"]["uid"]
                          and readback.get("data") == resource["data"])
        lab.check("positive", f"{variant} decision and trusted fixture bundle persist in an immutable ConfigMap",
                  exact_readback, {"name": config_name,
                                   "immutable": readback.get("immutable"), "exact_data_readback": exact_readback})
        observations["configmaps"][variant] = {
            "apiVersion": readback.get("apiVersion"), "kind": readback.get("kind"),
            "metadata": {key: readback.get("metadata", {}).get(key)
                         for key in ("name", "namespace", "uid", "resourceVersion", "labels")},
            "immutable": readback.get("immutable"), "data": readback.get("data"),
        }

        modes = ("bypass", "enforce") if variant == "missing-owner" else ("enforce",)
        for mode in modes:
            job_name = _resource_name(f"{variant}-{'bypass' if mode == 'bypass' else 'review'}")
            lab.create(_job(job_name, config_name, mode))
            observed = _observe_job(lab, job_name)
            result_key = f"{variant}-{mode}" if variant == "missing-owner" else variant
            results[result_key] = observed
            observations["jobs"][result_key] = observed

    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    versions = sorted({node.get("status", {}).get("nodeInfo", {}).get("kubeletVersion") for node in nodes})
    observations["node_kubelet_versions"] = versions
    (lab.evidence / "decision-workflow.raw.json").write_text(
        json.dumps(observations, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    bypass = results["missing-owner-bypass"]
    lab.check("red", "The bypass path accepts the same ownerless synthetic approval record without validation",
              bypass["job_condition"] == "Complete" and bypass["exit_code"] == 0
              and bypass["outcome"].get("decision") == "accepted_without_validation"
              and bypass["outcome"].get("validation_performed") is False,
              {"job_condition": bypass["job_condition"], "exit_code": bypass["exit_code"],
               "outcome": bypass["outcome"]})

    expected_errors = {
        "missing-owner-enforce": "owner_missing_or_untrusted",
        "failed-integrity": "integrity_fixture_not_bound_to_target",
        "missing-reason": "reason_missing_or_too_short",
        "untrusted-reference": "evidence_reference_untrusted_or_incomplete",
        "wrong-target": "rollback_target_untrusted_or_mismatched",
        "unresolved-evidence": "unresolved_evidence_not_owned_and_explicitly_dispositioned",
    }
    for variant, error in expected_errors.items():
        item = results[variant]
        blocked = (item["job_condition"] == "Failed" and item["exit_code"] == 1
                   and item["outcome"].get("decision") == "blocked"
                   and error in item["outcome"].get("errors", []))
        lab.check("green", f"The enforced workflow blocks {variant} with its field-specific reason",
                  blocked, {"job_condition": item["job_condition"], "exit_code": item["exit_code"],
                            "expected_error": error, "outcome": item["outcome"]})

    positive = results["positive"]
    nodes_ok = bool(nodes) and versions == ["v1.36.1"]
    lab.check("positive", "The disposable cluster reports Kubernetes v1.36.1 nodes",
              nodes_ok, {"node_count": len(nodes), "kubelet_versions": versions})
    accepted = (positive["job_condition"] == "Complete" and positive["exit_code"] == 0
                and positive["outcome"].get("decision") == "approved_fixture_only_conditional"
                and positive["outcome"].get("rollback_target") == TARGET_REF
                and positive["outcome"].get("unresolved_count") == 1
                and positive["outcome"].get("production_readiness") == "unverified")
    lab.check("positive", "A trusted fixture-only rollback decision preserves its owned unresolved evidence",
              accepted, {"job_condition": positive["job_condition"], "exit_code": positive["exit_code"],
                         "outcome": positive["outcome"]})
