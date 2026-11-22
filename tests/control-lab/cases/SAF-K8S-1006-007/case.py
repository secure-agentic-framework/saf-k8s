"""Probe a fixture-bound SSDF 1.1 evidence-gap record in disposable Kind."""
import hashlib
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
NAMESPACE = "saf-test"
API_GROUP = "saf-lab.example"
API_VERSION = "v1alpha1"
PLURAL = "ssdfassessments"
POLICY = "saf-k8s-1006-007-fixture-evidence-gate"
VAP = "saf-k8s-1006-007-fixture-evidence-validation"
OWNER = "fixture-owner-placeholder"
REVIEWER = "fixture-reviewer-placeholder"
EXPECTED_FIXTURE_SHA256 = {
    "mock-workload.json": "ae3ddc1eee04fd1b2e43eeed6617ae8b533dead2e9ce5bf9f2f5379b5c64fd68",
    "ssdf-v1.1-tasks.json": "b9631e4514f8cd3774986949436b76e789357897900af3d9844c5ab2ed12fd46",
    "synthetic-control-evidence.json": "8199f680d67194aea6a2079d0a49bbf0dc950be1c430a97c55d68aab4a41c2ac",
}
SCOPE = (
    "One disposable Kind cluster on the lab-pinned Kubernetes v1.36.1 node image. A case-owned "
    "ValidatingAdmissionPolicy gates a synthetic namespaced SSDF 1.1 assessment. It checks the "
    "complete NIST task-ID inventory, local fixture SHA-256 references, and owner-attributed, "
    "reviewable gap/not-applicable/unassessed statements. The assessment and mock AI workload "
    "contain reserved placeholders only; no workload is launched. This tests record shape and "
    "admission behavior, not organizational SSDF conformity or production practice."
)


def _read_json(path):
    return json.loads(path.read_text())


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _task_rows(catalog):
    rows = []
    for group in catalog["groups"]:
        for practice, task_ids in group["practices"].items():
            for task_id in task_ids:
                rows.append({"taskId": task_id, "groupId": group["id"], "practiceId": practice})
    return rows


def _fixture_refs(digests):
    return [
        {"path": name, "digest": "sha256:" + digest}
        for name, digest in sorted(digests.items())
    ]


def _assessment(task_rows, digests):
    evidence = {"path": "synthetic-control-evidence.json",
                "digest": "sha256:" + digests["synthetic-control-evidence.json"]}
    tasks = []
    for index, row in enumerate(task_rows):
        status = "gap" if index == 0 else "not_applicable" if index == 1 else "unassessed"
        tasks.append({
            **row,
            "status": status,
            "owner": OWNER,
            "rationale": "Synthetic fixture statement; applicability and implementation require human review.",
            "review": {"owner": REVIEWER, "status": "pending"},
            "evidenceRef": evidence,
        })
    return {
        "apiVersion": f"{API_GROUP}/{API_VERSION}",
        "kind": "SSDFAssessment",
        "metadata": {"name": "fixture-ssdf-review", "namespace": NAMESPACE,
                     "labels": {"saf-lab.example/case": "SAF-K8S-1006-007"}},
        "spec": {
            "sourceVersion": "NIST SP 800-218 SSDF 1.1",
            "subject": "fixture:synthetic-ai-workload",
            "disposition": "evidence_gap_review_required",
            "fixtureSetDigest": "sha256:" + digests["ssdf-v1.1-tasks.json"],
            "fixtureRefs": _fixture_refs(digests),
            "tasks": tasks,
        },
    }


def _crd():
    task_schema = {
        "type": "object", "required": ["taskId", "groupId", "practiceId", "status", "owner",
                                         "rationale", "review", "evidenceRef"],
        "properties": {
            "taskId": {"type": "string"}, "groupId": {"type": "string"},
            "practiceId": {"type": "string"},
            "status": {"type": "string", "enum": ["supported", "gap", "not_applicable", "unassessed"]},
            "owner": {"type": "string"}, "rationale": {"type": "string"},
            "review": {"type": "object", "required": ["owner", "status"], "properties": {
                "owner": {"type": "string"},
                "status": {"type": "string", "enum": ["pending", "accepted", "rejected"]},
            }},
            "evidenceRef": {"type": "object", "required": ["path", "digest"], "properties": {
                "path": {"type": "string"}, "digest": {"type": "string"},
            }},
        },
    }
    return {
        "apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
        "metadata": {"name": f"{PLURAL}.{API_GROUP}"},
        "spec": {"group": API_GROUP, "scope": "Namespaced", "names": {
            "plural": PLURAL, "singular": "ssdfassessment", "kind": "SSDFAssessment",
            "shortNames": ["ssdfa"],
        }, "versions": [{"name": API_VERSION, "served": True, "storage": True,
                         "schema": {"openAPIV3Schema": {
                             "type": "object", "required": ["spec"],
                             "properties": {"spec": {"type": "object", "required": [
                                 "sourceVersion", "subject", "disposition", "fixtureSetDigest",
                                 "fixtureRefs", "tasks"], "properties": {
                                     "sourceVersion": {"type": "string"}, "subject": {"type": "string"},
                                     "disposition": {"type": "string"},
                                     "fixtureSetDigest": {"type": "string"},
                                     "fixtureRefs": {"type": "array", "maxItems": 3, "items": {"type": "object",
                                         "required": ["path", "digest"], "properties": {
                                             "path": {"type": "string"}, "digest": {"type": "string"},
                                         }}},
                                     "tasks": {"type": "array", "maxItems": 42, "items": task_schema},
                                 }}}
                         }}}]}}


def _vap(task_rows, digests):
    task_ids = [row["taskId"] for row in task_rows]
    allowed_ids = json.dumps(task_ids)
    accepted_refs = " || ".join(
        f"(r.path == {json.dumps(name)} && r.digest == {json.dumps('sha256:' + digest)})"
        for name, digest in sorted(digests.items())
    )
    evidence_digest = "sha256:" + digests["synthetic-control-evidence.json"]
    fixture_paths_present = " && ".join(
        f"object.spec.fixtureRefs.exists(r, r.path == {json.dumps(name)} && r.digest == {json.dumps('sha256:' + digest)})"
        for name, digest in sorted(digests.items())
    )
    validations = [
        {"expression": f"object.spec.sourceVersion == 'NIST SP 800-218 SSDF 1.1' && object.spec.disposition == 'evidence_gap_review_required'",
         "message": "fixture assessment must declare SSDF 1.1 and remain review-required"},
        {"expression": f"object.spec.fixtureSetDigest == 'sha256:{digests['ssdf-v1.1-tasks.json']}'",
         "message": "fixture task inventory digest must match the pinned local task fixture"},
        {"expression": f"object.spec.fixtureRefs.size() == {len(digests)} && object.spec.fixtureRefs.all(r, {accepted_refs}) && {fixture_paths_present}",
         "message": "fixture references must match the allowlisted local paths and SHA-256 digests"},
        {"expression": f"object.spec.tasks.size() == {len(task_ids)} && {allowed_ids}.all(id, object.spec.tasks.exists(t, t.taskId == id)) && object.spec.tasks.all(t, t.taskId in {allowed_ids})",
         "message": f"all {len(task_ids)} SSDF 1.1 task IDs must appear exactly once"},
        {"expression": "object.spec.tasks.all(t, t.groupId == t.taskId.substring(0, 2) && t.practiceId == t.taskId.substring(0, 4))",
         "message": "each SSDF task must retain its exact group and practice identifier"},
        {"expression": "object.spec.tasks.all(t, t.owner.matches('^[a-z][a-z0-9-]{2,63}$') && t.rationale.size() > 0 && t.review.owner.matches('^[a-z][a-z0-9-]{2,63}$') && t.review.status in ['pending', 'accepted', 'rejected'])",
         "message": "each statement must retain an accountable owner, rationale, and review record"},
        {"expression": f"object.spec.tasks.all(t, t.evidenceRef.path == 'synthetic-control-evidence.json' && t.evidenceRef.digest == '{evidence_digest}')",
         "message": "each task statement must bind to the immutable synthetic evidence fixture"},
        {"expression": "object.spec.tasks.all(t, t.status in ['gap', 'not_applicable', 'unassessed'])",
         "message": "synthetic-only fixtures cannot assert a supported SSDF task status"},
    ]
    return {
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": VAP},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {"resourceRules": [{"apiGroups": [API_GROUP], "apiVersions": [API_VERSION],
                "operations": ["CREATE", "UPDATE"], "resources": [PLURAL]}]},
            "validations": validations,
        },
    }


def _binding():
    return {
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": POLICY},
        "spec": {"policyName": VAP, "validationActions": ["Deny"],
                  "matchResources": {"namespaceSelector": {"matchLabels": {
                      "saf-lab.example/ssdf-assessment": "enabled"}}}},
    }


def _submit(lab, assessment):
    return lab.kubectl("create", "-f", "-", "-o", "json", "--dry-run=server",
                       payload=json.dumps(assessment), allow_failure=True)


def _denied(result, marker):
    return (result.returncode != 0 and VAP in result.stderr and marker in result.stderr)


def run(lab):
    catalog_path = FIXTURES / "ssdf-v1.1-tasks.json"
    expected_files = [catalog_path, FIXTURES / "synthetic-control-evidence.json",
                      FIXTURES / "mock-workload.json"]
    digests = {path.name: _sha256(path) for path in expected_files}
    if digests != EXPECTED_FIXTURE_SHA256:
        lab.block("A local fixture hash differs from the immutable case-pinned SHA-256 allowlist")
    catalog = _read_json(catalog_path)
    rows = _task_rows(catalog)
    groups = [(group["id"], group["name"], len(group["practices"])) for group in catalog["groups"]]
    task_ids = [row["taskId"] for row in rows]
    if catalog.get("version") != "1.1" or len(rows) != 42 or len(set(task_ids)) != 42:
        lab.block("The checked-in SSDF v1.1 task inventory is malformed or incomplete")
    (lab.evidence / "ssdf-fixture-verification.json").write_text(json.dumps({
        "fixture_digests": {name: {"expected": "sha256:" + EXPECTED_FIXTURE_SHA256[name],
                                   "observed": "sha256:" + digest, "matched": digest == EXPECTED_FIXTURE_SHA256[name]}
                            for name, digest in digests.items()},
        "group_practice_task_counts": [{"group": group, "name": name, "practices": practices}
                                       for group, name, practices in groups],
        "task_count": len(rows), "task_ids": task_ids,
        "synthetic_only": True,
    }, indent=2) + "\n")

    server = json.loads(lab.kubectl("version", "-o", "json").stdout).get("serverVersion", {}).get("gitVersion")
    lab.check("positive", "The case is running against the intended disposable Kubernetes v1.36.1 API",
              server == "v1.36.1", {"server_git_version": server})
    lab.kubectl("apply", "-f", "-", payload=json.dumps(_crd()))
    lab.kubectl("wait", "--for=condition=Established", f"crd/{PLURAL}.{API_GROUP}", "--timeout=30s")
    lab.kubectl("label", "namespace", NAMESPACE, "saf-lab.example/ssdf-assessment=enabled")

    assessment = _assessment(rows, digests)
    broken = json.loads(json.dumps(assessment))
    broken["spec"]["tasks"].pop()
    baseline = _submit(lab, broken)
    lab.check("red", "Without the VAP, the API admits a synthetic evidence-gap record with one missing task",
              baseline.returncode == 0, {"admitted_without_gate": baseline.returncode == 0,
                                         "server_side_dry_run": True})

    lab.kubectl("apply", "-f", "-", payload=json.dumps(_vap(rows, digests)))
    lab.kubectl("apply", "-f", "-", payload=json.dumps(_binding()))
    missing_message = f"all {len(rows)} SSDF 1.1 task IDs must appear exactly once"
    deadline = time.monotonic() + 40
    while True:
        missing_result = _submit(lab, broken)
        if _denied(missing_result, missing_message) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    if not _denied(missing_result, missing_message):
        lab.block("The named admission gate did not reject the incomplete fixture: " + missing_result.stderr.strip())

    accepted = _submit(lab, assessment)
    lab.check("positive", "The gate admits a complete, immutable, owner-attributed assessment while keeping gaps review-required",
              accepted.returncode == 0,
              {"admitted": accepted.returncode == 0, "task_count": len(rows),
               "gap_review_pending": assessment["spec"]["tasks"][0]["review"]["status"] == "pending",
               "not_applicable_review_pending": assessment["spec"]["tasks"][1]["review"]["status"] == "pending",
               "disposition": assessment["spec"]["disposition"]})

    lab.check("green", "The enabled gate rejects a record missing a required SSDF task",
              _denied(missing_result, missing_message),
              {"expected_rule_observed": _denied(missing_result, missing_message),
               "policy_denial": VAP in missing_result.stderr})

    ownerless = json.loads(json.dumps(assessment))
    ownerless["spec"]["tasks"][0]["owner"] = ""
    ownerless_message = "each statement must retain an accountable owner, rationale, and review record"
    ownerless_result = _submit(lab, ownerless)
    lab.check("green", "The enabled gate rejects a gap statement without its accountable owner",
              _denied(ownerless_result, ownerless_message),
              {"expected_rule_observed": _denied(ownerless_result, ownerless_message),
               "policy_denial": VAP in ownerless_result.stderr})

    tampered = json.loads(json.dumps(assessment))
    tampered["spec"]["fixtureRefs"][0]["digest"] = "sha256:" + "0" * 64
    reference_message = "fixture references must match the allowlisted local paths and SHA-256 digests"
    tampered_result = _submit(lab, tampered)
    lab.check("green", "The enabled gate rejects an altered immutable fixture digest",
              _denied(tampered_result, reference_message),
              {"expected_rule_observed": _denied(tampered_result, reference_message),
               "policy_denial": VAP in tampered_result.stderr})

    stored = lab.create(assessment)
    version = stored["metadata"]["resourceVersion"]
    unsupported = lab.kubectl(
        "patch", f"{PLURAL}.{API_GROUP}", stored["metadata"]["name"], "--type=json",
        "-p", json.dumps([{"op": "replace", "path": "/spec/tasks/0/status", "value": "supported"}]),
        allow_failure=True,
    )
    check = _denied(unsupported, "synthetic-only fixtures cannot assert a supported SSDF task status")
    accepted = json.loads(lab.kubectl("get", f"{PLURAL}.{API_GROUP}", stored["metadata"]["name"],
                                      "-o", "json").stdout)
    unchanged = accepted["metadata"]["resourceVersion"] == version and accepted["spec"] == assessment["spec"]
    lab.check("green", "An unsupported status update is denied and the persisted review remains unchanged",
              check and unchanged, {"policy_denial": check, "stored_assessment_unchanged": unchanged})
    (lab.evidence / "admission-decisions.json").write_text(json.dumps({
        "baseline_admitted": baseline.returncode == 0,
        "stored_assessment": accepted["spec"],
        "missing_task_denial": missing_result.stderr,
        "ownerless_denial": ownerless_result.stderr,
        "tampered_digest_denial": tampered_result.stderr,
        "unsupported_update_denial": unsupported.stderr,
    }, indent=2, sort_keys=True) + "\n")
