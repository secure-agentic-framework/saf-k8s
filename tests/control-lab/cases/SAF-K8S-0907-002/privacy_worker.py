"""Consume only fixed invented training data and emit minimal access records."""
import json
import os
from pathlib import Path
import sys
import hashlib

from data_fixture import APPROVED, BAD, DIRECT_IDENTIFIER_FIELDS, canonical, classify, digest, receipt, sanitize

ROOT = Path("/store")
OUTPUT = ROOT / "approved" / "training.json"
PURPOSE_POLICY_PATH = Path("/purpose/policy.json")
PURPOSE_POLICY_SHA256 = "376929ad97b8db142e95e42fa0f76acca43782918456eb3fa37922987d1bcce5"
PURPOSE_ROOT = ROOT / "purpose"
PURPOSE_OUTPUT = PURPOSE_ROOT / "derivative-minimized-v1.json"


def emit(row):
    print(canonical(row), flush=True)


def write(path, data):
    path.write_text(canonical(data) + "\n")
    path.chmod(0o640)


def baseline():
    for dataset in (APPROVED, BAD):
        write(ROOT / "baseline" / (dataset["dataset_id"] + ".json"), dataset)
    emit({"baseline_published_both": True})


def process():
    output = sanitize(APPROVED)
    write(OUTPUT, output)
    write(ROOT / "held" / "receipt.json", receipt(BAD, sanitize(BAD)))
    emit({"approved": receipt(APPROVED, output), "held": classify(BAD)})


def inspect():
    excluded = {row[k] for src in (APPROVED, BAD) for row in src["rows"]
                for k in DIRECT_IDENTIFIER_FIELDS}
    baseline = ROOT / "baseline"
    approved_raw = json.loads((baseline / (APPROVED["dataset_id"] + ".json")).read_text())
    held_raw = json.loads((baseline / (BAD["dataset_id"] + ".json")).read_text())
    value = OUTPUT.read_text()
    retained = json.loads(value)
    held = ROOT / "held"
    checks = {
        "unrestricted_baseline_retained_direct_identifiers": any(
            field in row for row in approved_raw["rows"] for field in DIRECT_IDENTIFIER_FIELDS
        ),
        "unrestricted_baseline_published_held_version": held_raw["dataset_id"] == BAD["dataset_id"],
        "approved_durable_output_matches_minimized_contract": retained == sanitize(APPROVED)
        and all(not any(k in row for k in DIRECT_IDENTIFIER_FIELDS) for row in retained["rows"])
        and all(item not in value for item in excluded),
        "held_dataset_has_disposition_only": sorted(path.name for path in held.iterdir()) == ["receipt.json"]
        and json.loads((held / "receipt.json").read_text()) == receipt(BAD, None),
        "approved_sha256": digest(retained),
    }
    emit(checks)


def read():
    event = {"event": "training-data-read", "dataset_id": APPROVED["dataset_id"],
             "principal": "system:serviceaccount:" + os.environ["POD_NAMESPACE"] + ":" + os.environ["POD_ACCOUNT"],
             "uid": os.getuid()}
    try:
        value = json.loads(OUTPUT.read_text())
    except PermissionError:
        emit({**event, "decision": "denied", "reason": "permission-denied"})
        return
    emit({**event, "decision": "allowed", "output_sha256": digest(value), "row_count": len(value["rows"])})


def purpose_policy():
    raw = PURPOSE_POLICY_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PURPOSE_POLICY_SHA256:
        raise ValueError("purpose_policy_digest_mismatch")
    return json.loads(raw)


def purpose_decision(dataset, purpose, principal_account, requested_parent_digest, policy):
    source = policy["source"]
    actual_digest = digest(dataset)
    if (dataset.get("dataset_id") != source["dataset_id"]
            or source["version"] != dataset.get("dataset_id")
            or dataset.get("approval") != source["approval"]
            or dataset.get("classification") != source["classification"]
            or actual_digest != source["sha256"]):
        return False, "source_scope_or_digest_mismatch"
    if principal_account != policy["principal_account"]:
        return False, "principal_not_approved"
    if purpose != policy["purpose"]:
        return False, "purpose_not_approved"
    if requested_parent_digest != source["sha256"]:
        return False, "parent_digest_not_approved"
    return True, "approved"


def purpose_process():
    policy = purpose_policy()
    account = os.environ.get("POD_ACCOUNT", "")
    principal_name = "system:serviceaccount:" + os.environ.get("POD_NAMESPACE", "") + ":" + account
    purpose = policy["purpose"]
    parent_digest = policy["source"]["sha256"]
    attempts = [
        ("wrong-purpose", APPROVED, "synthetic-fixture-inference-v1", account, parent_digest),
        ("wrong-version", {**APPROVED, "dataset_id": "fixture-training-approved-v2"}, purpose, account, parent_digest),
        ("wrong-parent-digest", APPROVED, purpose, account, "0" * 64),
    ]
    denied = {}
    for name, dataset, requested_purpose, requester, requested_parent in attempts:
        accepted, reason = purpose_decision(dataset, requested_purpose, requester, requested_parent, policy)
        target = PURPOSE_ROOT / ("denied-" + name + ".json")
        denied[name] = {"accepted": accepted, "reason": reason, "denied_output_absent": not target.exists()}

    accepted, reason = purpose_decision(APPROVED, purpose, account, parent_digest, policy)
    created = False
    derivative_digest = None
    if accepted:
        minimized = sanitize(APPROVED)
        derivative = {
            "dataset_id": policy["derivative"]["dataset_id"],
            "version": policy["derivative"]["version"],
            "approval": policy["derivative"]["approval"],
            "classification": policy["derivative"]["classification"],
            "purpose": policy["derivative"]["purpose"],
            "parent_dataset_id": policy["derivative"]["parent_dataset_id"],
            "parent_sha256": digest(APPROVED),
            "data": minimized,
        }
        derivative_digest = digest(derivative)
        if (derivative_digest == policy["derivative"]["sha256"]
                and digest(minimized) == policy["derivative"]["data_sha256"]):
            write(PURPOSE_OUTPUT, derivative)
            created = True
    emit({"policy_digest_matches_pin": True,
          "principal_account": account,
          "principal_name": principal_name,
          "approved_request": {"accepted": accepted, "reason": reason,
                               "derivative_created": created,
                               "derivative_digest_matches_policy": derivative_digest == policy["derivative"]["sha256"],
                               "derivative_sha256": derivative_digest},
          "denied_requests": denied,
          "denied_outputs_absent": all(item["denied_output_absent"] and not item["accepted"]
                                        for item in denied.values())})


def purpose_outsider():
    policy = purpose_policy()
    account = os.environ.get("POD_ACCOUNT", "")
    accepted, reason = purpose_decision(APPROVED, policy["purpose"], account,
                                        policy["source"]["sha256"], policy)
    emit({"policy_digest_matches_pin": True, "principal_account": account,
          "request_denied": not accepted, "reason": reason,
          "derivative_write_not_attempted": not accepted})


def inspect_purpose():
    policy = purpose_policy()
    raw = PURPOSE_OUTPUT.read_text()
    derivative = json.loads(raw)
    source = policy["source"]
    target = policy["derivative"]
    forbidden_values = {row[key] for row in APPROVED["rows"] for key in DIRECT_IDENTIFIER_FIELDS}
    emit({"derivative_present": True,
          "source_id_bound": derivative.get("parent_dataset_id") == source["dataset_id"],
          "source_digest_bound": derivative.get("parent_sha256") == source["sha256"] == digest(APPROVED),
          "target_id_version_purpose_bound": derivative.get("dataset_id") == target["dataset_id"]
          and derivative.get("version") == target["version"]
          and derivative.get("purpose") == target["purpose"],
          "target_approval_and_classification_bound": derivative.get("approval") == target["approval"]
          and derivative.get("classification") == target["classification"],
          "approved_minimized_data_exact": derivative.get("data") == sanitize(APPROVED)
          and digest(derivative["data"]) == target["data_sha256"],
          "derivative_digest_exact": digest(derivative) == target["sha256"],
          "derivative_sha256": digest(derivative),
          "identifier_fields_and_values_absent": all(key not in raw for key in DIRECT_IDENTIFIER_FIELDS)
          and not any(value in raw for value in forbidden_values),
          "row_count": len(derivative["data"]["rows"]),
          "file_sha256": hashlib.sha256(raw.encode()).hexdigest()})


if __name__ == "__main__":
    {"baseline": baseline, "process": process, "inspect": inspect, "read": read,
     "purpose": purpose_process, "purpose-outsider": purpose_outsider,
     "inspect-purpose": inspect_purpose}[sys.argv[1]]()
