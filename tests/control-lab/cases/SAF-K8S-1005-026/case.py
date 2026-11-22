"""Demonstrate synthetic custody transitions and an authorization gate."""
import hashlib
from hashlib import sha256
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
CONTROL_ID = "SAF-K8S-1005-026"
NAMESPACE = "saf-test"
FIXTURE_CONFIG = "saf-1005-026-vault"
WORKER_CONFIG = "saf-1005-026-worker"
JOB_NAME = "saf-1005-026-custody"
LABEL_KEY = "saf-k8s.example/control"
LABEL_VALUE = "1005-026"
WORKER_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
EXPECTED_ARTIFACT_SHA256 = (
    "979aa151b3ed8f6168e201e52771ce9c56465b6905a7c2c2002032f7eb0cc596"
)
SCOPE = (
    "One disposable single-node Kind v1.36.1 cluster, one immutable ConfigMap holding a checked-in "
    "inert text fixture, and one tokenless digest-pinned Python mock Job. The Job compares the same "
    "fictional transfer with a pending authorization label when the workflow gate is disabled and "
    "enabled, then performs one approved positive transfer. It emits synthetic hash-linked custody "
    "records only. This does not handle real evidence, establish actor identity or authority, seize "
    "assets, prove durable/WORM storage, or establish legal admissibility or production procedure."
)


def audit_chain(events, fixture_id):
    previous_digest = "GENESIS"
    if len(events) != 3:
        return False
    for sequence, event in enumerate(events, start=1):
        payload = {field: value for field, value in event.items() if field != "event_sha256"}
        digest = sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if (event["sequence"] != sequence or event["fixture_id"] != fixture_id
                or event["artifact_sha256"] != EXPECTED_ARTIFACT_SHA256
                or event["previous_event_sha256"] != previous_digest
                or event["event_sha256"] != digest):
            return False
        previous_digest = digest
    return True


def run(lab):
    artifact_bytes = (FIXTURES / "inert-evidence.txt").read_bytes()
    artifact = artifact_bytes.decode("utf-8")
    case_record = (FIXTURES / "case.json").read_text(encoding="utf-8")
    worker = (FIXTURES / "worker.py").read_text(encoding="utf-8")
    record = json.loads(case_record)
    if (record.get("control_id") != CONTROL_ID or record.get("fixture_only") is not True
            or record.get("artifact_sha256") != EXPECTED_ARTIFACT_SHA256
            or sha256(artifact_bytes).hexdigest() != EXPECTED_ARTIFACT_SHA256
            or record.get("labels_are_credentials") is not False
            or record.get("timestamps_are_synthetic") is not True):
        lab.block("Case metadata is not the pinned synthetic fixture")

    vault = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": FIXTURE_CONFIG, "namespace": NAMESPACE,
                     "labels": {LABEL_KEY: LABEL_VALUE,
                                "saf-k8s.example/evidence-id": record["fixture_id"],
                                "saf-k8s.example/storage-class": "immutable-fixture-only"}},
        "immutable": True,
        "data": {"inert-evidence.txt": artifact},
    }
    worker_config = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": WORKER_CONFIG, "namespace": NAMESPACE,
                     "labels": {LABEL_KEY: LABEL_VALUE}},
        "immutable": True,
        "data": {"case.json": case_record, "worker.py": worker},
    }
    lab.create(vault)
    lab.create(worker_config)

    observed_vault = json.loads(lab.kubectl(
        "get", "configmap", FIXTURE_CONFIG, "-o", "json",
    ).stdout)
    observed_data = observed_vault.get("data", {}).get("inert-evidence.txt")
    storage_ok = (
        observed_vault.get("immutable") is True
        and observed_vault.get("metadata", {}).get("labels", {}).get(LABEL_KEY) == LABEL_VALUE
        and observed_vault.get("metadata", {}).get("labels", {}).get(
            "saf-k8s.example/evidence-id") == record["fixture_id"]
        and observed_data == artifact
    )

    mutation = lab.kubectl(
        "patch", "configmap", FIXTURE_CONFIG, "--type=merge",
        "-p", '{"data":{"inert-evidence.txt":"SYNTHETIC-CHANGED"}}',
        allow_failure=True,
    )
    after_mutation = json.loads(lab.kubectl(
        "get", "configmap", FIXTURE_CONFIG, "-o", "json",
    ).stdout)
    rejected_by_immutability = (mutation.returncode != 0
                                and f'The ConfigMap "{FIXTURE_CONFIG}" is invalid: data: Forbidden:' in mutation.stderr
                                and "field is immutable when `immutable` is set" in mutation.stderr)
    immutable_storage_holds = (
        rejected_by_immutability
        and after_mutation["metadata"]["uid"] == observed_vault["metadata"]["uid"]
        and after_mutation.get("immutable") is True
        and after_mutation.get("data", {}).get("inert-evidence.txt") == artifact
    )
    lab.check(
        "green", "Kubernetes immutable ConfigMap preserves the fixture after a data-update attempt",
        storage_ok and immutable_storage_holds,
        {"immutable": observed_vault.get("immutable"),
         "fixture_readback_matches": observed_data == artifact,
         "update_rejected_by_immutability": rejected_by_immutability,
         "bytes_unchanged_after_attempt": (
             after_mutation.get("data", {}).get("inert-evidence.txt") == artifact),
         "evidence_id_label": record["fixture_id"],
         "artifact_sha256_expected": EXPECTED_ARTIFACT_SHA256},
    )

    lab.create({
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": JOB_NAME, "namespace": NAMESPACE,
                     "labels": {LABEL_KEY: LABEL_VALUE}},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 90,
            "template": {
                "metadata": {"labels": {LABEL_KEY: LABEL_VALUE}},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{
                        "name": "custody-fixture", "image": WORKER_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "-B", "/case/worker.py"],
                        "securityContext": {"allowPrivilegeEscalation": False,
                                            "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                        "volumeMounts": [
                            {"name": "vault", "mountPath": "/vault", "readOnly": True},
                            {"name": "case", "mountPath": "/case", "readOnly": True},
                        ],
                        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                      "limits": {"cpu": "100m", "memory": "64Mi"}},
                    }],
                    "volumes": [
                        {"name": "vault", "configMap": {"name": FIXTURE_CONFIG,
                                                           "items": [{"key": "inert-evidence.txt",
                                                                      "path": "inert-evidence.txt"}]}},
                        {"name": "case", "configMap": {"name": WORKER_CONFIG,
                                                          "items": [{"key": "case.json",
                                                                     "path": "case.json"},
                                                                    {"key": "worker.py",
                                                                     "path": "worker.py"}]}},
                    ],
                },
            },
        },
    })
    lab.kubectl("wait", f"job/{JOB_NAME}", "--for=condition=complete", "--timeout=120s", timeout=130)
    raw = lab.kubectl("logs", f"job/{JOB_NAME}").stdout.strip()
    (lab.evidence / "custody-observations.raw.json").write_text(raw + "\n", encoding="utf-8")
    raw_sha256 = hashlib.sha256((raw + "\n").encode("utf-8")).hexdigest()
    receipt_config = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "saf-1005-026-custody-receipts", "namespace": NAMESPACE,
                     "labels": {LABEL_KEY: LABEL_VALUE,
                                "saf-k8s.example/evidence-id": record["fixture_id"]},
                     "annotations": {"saf-k8s.example/receipt-sha256": raw_sha256}},
        "immutable": True,
        "data": {"custody-observations.raw.json": raw + "\n"},
    }
    lab.create(receipt_config)
    stored_receipt = json.loads(lab.kubectl(
        "get", "configmap", "saf-1005-026-custody-receipts", "-o", "json",
    ).stdout)
    receipt_readback = stored_receipt.get("data", {}).get("custody-observations.raw.json")
    lab.check(
        "green", "Hash-linked custody receipts are read back from an immutable labeled ConfigMap",
        stored_receipt.get("immutable") is True and receipt_readback == raw + "\n"
        and hashlib.sha256(receipt_readback.encode("utf-8")).hexdigest() == raw_sha256
        and stored_receipt.get("metadata", {}).get("annotations", {}).get(
            "saf-k8s.example/receipt-sha256") == raw_sha256,
        {"immutable": stored_receipt.get("immutable"),
         "receipt_readback_matches": receipt_readback == raw + "\n",
         "receipt_sha256": raw_sha256,
         "receipt_sha256_annotation_matches": stored_receipt.get("metadata", {}).get(
             "annotations", {}).get("saf-k8s.example/receipt-sha256") == raw_sha256},
    )
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as error:
        lab.block(f"Synthetic custody worker returned malformed JSON ({error})")

    digest_ok = (
        result.get("artifact_sha256_expected") == EXPECTED_ARTIFACT_SHA256
        and result.get("artifact_sha256_observed") == EXPECTED_ARTIFACT_SHA256
    )
    no_gate = result["without_gate_pending_transfer"]
    same_transfer = no_gate["transfer_id"] == "SYN-TRANSFER-1005-026-001"
    lab.check(
        "red", "The same pending fictional transfer completes when its workflow gate is disabled",
        digest_ok and same_transfer and no_gate["gate_enabled"] is False
        and no_gate["state"] == "transferred" and no_gate["chain_valid"] is True
        and no_gate["events"][-1]["authorization_status"] == "pending"
        and no_gate["events"][-1]["outcome"] == "completed-without-approval-gate",
        {"transfer_id": no_gate["transfer_id"], "gate_enabled": no_gate["gate_enabled"],
         "state": no_gate["state"], "authorization_status": no_gate["events"][-1]["authorization_status"],
         "custody_chain_valid": no_gate["chain_valid"], "artifact_sha256_matches": digest_ok},
    )

    gated = result["with_gate_pending_transfer"]
    lab.check(
        "green", "The gate blocks that same transfer while authorization is pending and retains the fixture",
        gated["transfer_id"] == no_gate["transfer_id"] and gated["gate_enabled"] is True
        and gated["authorization"] == no_gate["authorization"]
        and gated["state"] == "retained-in-immutable-storage"
        and gated["chain_valid"] is True and gated["events"][-1]["outcome"] == "blocked"
        and gated["events"][-1]["requested_to_label"] == "urn:example:review:sandbox-counsel"
        and gated["events"][-1]["from_label"] == gated["events"][-1]["to_label"]
        and gated["events"][-1]["authorization_status"] == "pending",
        {"transfer_id": gated["transfer_id"], "gate_enabled": gated["gate_enabled"],
         "state": gated["state"], "last_event_outcome": gated["events"][-1]["outcome"],
         "last_event_authorization_status": gated["events"][-1]["authorization_status"],
         "requested_destination_label": gated["events"][-1]["requested_to_label"],
         "actual_destination_label": gated["events"][-1]["to_label"],
         "custody_chain_valid": gated["chain_valid"],
         "item_moved": gated["events"][-1]["from_label"] != gated["events"][-1]["to_label"]},
    )

    approved = result["with_gate_approved_transfer"]
    final = approved["events"][-1]
    independent_matches = {
        "pending_without_gate": audit_chain(no_gate["events"], record["fixture_id"]),
        "pending_with_gate": audit_chain(gated["events"], record["fixture_id"]),
        "approved_with_gate": audit_chain(approved["events"], record["fixture_id"]),
    }
    edited_events = [dict(event) for event in approved["events"]]
    edited_events[1]["to_label"] += "-unrecorded-change"
    edited_chain_valid = audit_chain(edited_events, record["fixture_id"])
    lab.check("green", "An independent verifier validates all emitted chains and rejects a changed event",
              all(independent_matches.values()) and not edited_chain_valid,
              {"original_chains_valid": independent_matches, "edited_chain_valid": edited_chain_valid})
    lab.check(
        "positive", "An explicitly approved and correctly scoped transfer completes through the gate",
        approved["transfer_id"] == no_gate["transfer_id"]
        and approved["gate_enabled"] is True and approved["state"] == "transferred"
        and approved["chain_valid"] is True and final["outcome"] == "completed"
        and final["authorization_status"] == "approved"
        and final["approver_role_label"] == "synthetic-incident-commander"
        and final["authorization_scope_label"] == f"transfer:{approved['transfer_id']}"
        and final["artifact_sha256"] == EXPECTED_ARTIFACT_SHA256
        and result.get("external_services_contacted") is False,
        {"transfer_id": approved["transfer_id"], "state": approved["state"],
         "authorization_label": final["authorization_label"],
         "authorization_status": final["authorization_status"],
         "approver_role_label": final["approver_role_label"],
         "authorization_scope_label": final["authorization_scope_label"],
         "custody_chain_valid": approved["chain_valid"],
         "artifact_sha256": final["artifact_sha256"],
         "external_services_contacted": result.get("external_services_contacted")},
    )
