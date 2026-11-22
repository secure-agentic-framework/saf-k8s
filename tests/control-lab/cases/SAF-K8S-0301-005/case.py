"""Validate a synthetic PSA exception register record through live admission."""
import json
from pathlib import Path
import time

HERE = Path(__file__).parent
NAMESPACE = "saf-0301-005-register"
GROUP = "security.saf-lab.example"
VERSION = "v1alpha1"
DENIAL = (
    "PSA exception register requires exact privileges, justification, risk owner, "
    "and compensating controls"
)
SCOPE = (
    "Live Kubernetes API admission for one case-owned, namespaced synthetic "
    "PSAExceptionRecord CRD. Compares one incomplete record before and after a "
    "ValidatingAdmissionPolicy, checks each required declaration independently, "
    "and persists one complete synthetic record. No Pod or other workload is "
    "created, no PSA exemption is installed, and deployed-exception enforcement, "
    "production registers, audit backends, and Secret data are out of scope."
)


def record(name, spec):
    return {
        "apiVersion": f"{GROUP}/{VERSION}",
        "kind": "PSAExceptionRecord",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": spec,
    }


INCOMPLETE = record("synthetic-incomplete", {
    "workloadRef": {
        "kind": "DaemonSet",
        "namespace": "synthetic-system",
        "name": "synthetic-device-agent",
    },
})

COMPLETE_SPEC = {
    "workloadRef": {
        "kind": "DaemonSet",
        "namespace": "synthetic-system",
        "name": "synthetic-device-agent",
    },
    "privileges": ["synthetic:device-access"],
    "justification": "Synthetic fixture requires the named device access for its declared function.",
    "riskOwner": "synthetic-risk-owner@example.invalid",
    "compensatingControls": ["synthetic:network-isolation-review"],
}


def submit(lab, obj, *, dry_run=True):
    flags = ["--dry-run=server"] if dry_run else []
    return lab.kubectl(
        "-n", NAMESPACE, "create", "-f", "-", "-o", "json", *flags,
        payload=json.dumps(obj), allow_failure=True,
    )


def policy_denied(result):
    return (
        result.returncode != 0
        and "(Forbidden)" in result.stderr
        and DENIAL in result.stderr
        and "saf-k8s-0301-005-complete-exception-register" in result.stderr
    )


def run(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("label", "namespace", NAMESPACE, "saf-k8s.example/case=0301-005")
    lab.apply(HERE / "exception-record-crd.yaml")
    lab.kubectl(
        "wait", "--for=condition=Established",
        "crd/psaexceptionrecords.security.saf-lab.example", "--timeout=45s",
    )

    # Red baseline: the same typed but incomplete object is valid to the API
    # schema and is accepted by real server admission before the register policy.
    before = submit(lab, INCOMPLETE)
    lab.check(
        "red",
        "API accepts the incomplete typed register record before policy",
        before.returncode == 0,
        before.stderr.strip() or "server-side dry-run admitted",
    )

    lab.apply(HERE / "admission-policy.yaml")
    deadline = time.monotonic() + 20
    after = submit(lab, INCOMPLETE)
    while not policy_denied(after) and time.monotonic() < deadline:
        time.sleep(0.5)
        after = submit(lab, INCOMPLETE)
    lab.check(
        "green",
        "The same incomplete record is rejected by the active admission policy",
        policy_denied(after),
        after.stderr.strip(),
    )

    # Isolate each required declaration to make the reason for rejection
    # reviewable; all these are inert server-side dry-runs of synthetic records.
    for field in ("privileges", "justification", "riskOwner", "compensatingControls"):
        partial_spec = dict(COMPLETE_SPEC)
        del partial_spec[field]
        result = submit(lab, record(f"synthetic-missing-{field.lower()}", partial_spec))
        lab.check(
            "green",
            f"Admission rejects a record missing {field}",
            policy_denied(result),
            result.stderr.strip(),
        )

    for field, empty_value in (("privileges", [" "]), ("justification", "  "),
                               ("riskOwner", "  "), ("compensatingControls", [""])):
        empty_spec = dict(COMPLETE_SPEC)
        empty_spec[field] = empty_value
        result = submit(lab, record(f"synthetic-empty-{field.lower()}", empty_spec))
        lab.check(
            "green",
            f"Admission rejects a blank {field} declaration",
            policy_denied(result),
            result.stderr.strip(),
        )

    # The only persisted object is a complete synthetic register record.
    complete = record("synthetic-complete", COMPLETE_SPEC)
    created = submit(lab, complete, dry_run=False)
    persisted = json.loads(lab.kubectl(
        "-n", NAMESPACE, "get", "psaexceptionrecord", "synthetic-complete", "-o", "json",
    ).stdout)
    lab.check(
        "positive",
        "Admission accepts and stores the explicitly complete synthetic record",
        created.returncode == 0 and persisted.get("spec") == COMPLETE_SPEC,
        persisted.get("spec"),
    )

    update = ("-n", NAMESPACE, "patch", "psaexceptionrecord", "synthetic-complete",
              "--type=merge", "-p")
    incomplete_change = lab.kubectl(*update, json.dumps({"spec": {"riskOwner": " "}}), allow_failure=True)
    stored = json.loads(lab.kubectl(
        "-n", NAMESPACE, "get", "psaexceptionrecord", "synthetic-complete", "-o", "json",
    ).stdout)["spec"]
    lab.check("green", "Removing the risk owner from an existing record is denied and preserves it",
              policy_denied(incomplete_change) and stored == COMPLETE_SPEC,
              {"forbidden_by_policy": policy_denied(incomplete_change), "original_record_preserved": stored == COMPLETE_SPEC})

    new_owner = "synthetic-next-owner@example.invalid"
    repaired = json.loads(lab.kubectl(
        *update, json.dumps({"spec": {"riskOwner": new_owner}}), "-o", "json",
    ).stdout)["spec"]
    lab.check("positive", "A complete update to the evidence record persists",
              repaired == {**COMPLETE_SPEC, "riskOwner": new_owner},
              {"expected_complete_update_persisted": repaired == {**COMPLETE_SPEC, "riskOwner": new_owner}})
