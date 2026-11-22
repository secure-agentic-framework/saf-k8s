"""Fixture-only contract checker; it never loads training code or model weights."""
import hashlib
import json
import sys


SCHEMA = "saf-k8s.example/ai-development-evidence/v1"
PROFILE = "NIST.SP.800-218A-2024-07"
TASKS = {
    "PO.3.3",  # Configure tools to generate artifacts of secure-development support.
    "PO.5.1",  # Separate and protect software-development environments.
    "PS.2.1",  # Make software-release integrity information available.
    "PS.3.1",  # Archive necessary files and supporting data for each release.
    "PS.3.2",  # Collect, safeguard, maintain, and share component provenance.
    "PW.3.2",  # Track known data provenance and document unknown provenance.
}


def _sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _reject(message):
    print("REJECT " + message, flush=True)
    raise SystemExit(23)


def _check_development(document):
    if document.get("schema") != SCHEMA:
        _reject("schema_version_mismatch")
    if document.get("profile") != PROFILE:
        _reject("profile_edition_mismatch")
    if document.get("evidence_scope") != "ai_model_development":
        _reject("development_scope_mismatch")

    refs = document.get("task_references", [])
    if not refs or any(item not in TASKS for item in refs):
        _reject("unknown_or_missing_profile_task_reference")
    if set(refs) != TASKS:
        _reject("profile_task_reference_set_mismatch")

    dataset = document.get("dataset", {})
    environment = document.get("environment", {})
    run = document.get("training_run", {})
    artifact = document.get("artifact", {})
    release = document.get("release", {})

    if dataset.get("version") != "1.0.0":
        _reject("dataset_version_missing_or_unexpected")
    if dataset.get("provenance_state") == "unknown":
        if dataset.get("source_ref") or not dataset.get("provenance_gap"):
            _reject("undocumented_dataset_provenance")
        print(json.dumps({"decision": "provenance_gap", "dataset_id": dataset.get("dataset_id"),
                          "provenance_state": "unknown", "gap": dataset["provenance_gap"],
                          "asserts_compliance": False}, sort_keys=True), flush=True)
        raise SystemExit(23)
    if dataset.get("provenance_state") != "known" or not dataset.get("source_ref", "").endswith(".example.invalid/dataset-v1"):
        _reject("dataset_provenance_fixture_mismatch")
    if _sha256(dataset.get("fixture_payload", "")) != dataset.get("sha256"):
        _reject("dataset_fixture_digest_mismatch")

    if environment.get("version") != "1.0.0":
        _reject("environment_version_missing_or_unexpected")
    if environment.get("isolation_observation") != "metadata_only_not_assessed":
        _reject("environment_protection_status_must_remain_unassessed")
    if run.get("version") != "1.0.0" or run.get("dataset_id") != dataset.get("dataset_id"):
        _reject("training_run_dataset_reference_mismatch")
    if run.get("dataset_version") != dataset.get("version") or run.get("dataset_sha256") != dataset.get("sha256"):
        _reject("training_run_dataset_integrity_reference_mismatch")
    if run.get("execution") != "not_performed" or run.get("fixture_only") is not True:
        _reject("training_fixture_must_remain_inert")
    if (run.get("environment_id") != environment.get("environment_id")
            or run.get("environment_version") != environment.get("version")):
        _reject("training_run_environment_reference_mismatch")
    if run.get("artifact_id") != artifact.get("artifact_id"):
        _reject("training_run_artifact_reference_mismatch")

    if artifact.get("version") != "1.0.0" or artifact.get("kind") != "metadata-only-placeholder":
        _reject("artifact_fixture_mismatch")
    if artifact.get("weights_present") is not False:
        _reject("model_weights_must_be_absent")
    if _sha256(artifact.get("fixture_payload", "")) != artifact.get("sha256"):
        _reject("artifact_fixture_digest_mismatch")
    if (run.get("artifact_version") != artifact.get("version")
            or run.get("artifact_sha256") != artifact.get("sha256")):
        _reject("training_run_artifact_provenance_mismatch")

    if release.get("version") != "1.0.0" or release.get("training_run_id") != run.get("run_id"):
        _reject("release_training_run_reference_mismatch")
    if (release.get("artifact_id") != artifact.get("artifact_id")
            or release.get("artifact_version") != artifact.get("version")
            or release.get("artifact_sha256") != artifact.get("sha256")):
        _reject("release_provenance_mismatch")

    unknown = document.get("organizational_state", {})
    if unknown.get("governance") != "unknown" or unknown.get("actual_operation") != "unknown":
        _reject("unknown_organizational_state_not_preserved")

    print(json.dumps({
        "decision": "fixture_consistent",
        "schema": SCHEMA,
        "profile": PROFILE,
        "task_references": sorted(refs),
        "dataset_version": dataset["version"],
        "training_run_version": run["version"],
        "artifact_version": artifact["version"],
        "release_version": release["version"],
        "environment_protection": "unknown",
        "organizational_governance": "unknown",
        "actual_operation": "unknown",
        "training_executed": False,
        "model_bytes_present": False,
        "asserts_compliance": False,
    }, sort_keys=True), flush=True)


def main():
    if len(sys.argv) != 3:
        _reject("usage_mismatch")
    path, scenario_name = sys.argv[1:]
    bundle = json.loads(open(path, encoding="utf-8").read())
    scenario = bundle.get("scenarios", {}).get(scenario_name)
    if scenario is None:
        _reject("scenario_missing")

    if scenario.get("evidence_scope") == "ai_system_deployment_and_operation":
        if scenario.get("schema") != SCHEMA or scenario.get("profile") != PROFILE:
            _reject("scope_boundary_fixture_mismatch")
        state = scenario.get("organizational_state", {})
        if state.get("governance") != "unknown" or state.get("actual_operation") != "unknown":
            _reject("unknown_organizational_state_not_preserved")
        print(json.dumps({
            "decision": "out_of_profile",
            "profile": PROFILE,
            "evidence_scope": scenario["evidence_scope"],
            "organizational_governance": "unknown",
            "actual_operation": "unknown",
            "asserts_compliance": False,
        }, sort_keys=True), flush=True)
        return

    _check_development(scenario)


if __name__ == "__main__":
    main()
