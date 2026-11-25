"""Verify write-key rotation and exact migration of owned inert API records."""

import base64
from copy import deepcopy
from datetime import date, timedelta
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

SCOPE = ("Native Secretbox key rotation for a dedicated custom resource on one disposable Kubernetes API server, "
         "plus a pure synthetic schedule and backup-retirement decision predicate with no operational actions.")
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
NAMESPACE = "saf-test"
GROUP = "rotation.saf.example"
RESOURCE = f"rotationmarkers.{GROUP}"
CONFIG_DIR = "/etc/kubernetes/saf-rotation-fixture"
OLD = "fixture-old-key"
NEW = "fixture-new-key"
MARKERS = {"pre-rotation": "fixture-public-before", "post-rotation": "fixture-public-after",
           "rollback-write": "fixture-public-during-rollback"}

# A separate, offline decision predicate. All inventory labels and dates below
# are fictional; this does not read or retire any key or backup.
PLANNER_CLOCK = date(2026, 11, 25)
PLANNER_CONTROL = "SAF-K8S-0102-006"


def planner_decision(plan, today=PLANNER_CLOCK):
    """Return accept/reason codes for a synthetic schedule/retention plan."""
    reasons = []
    if plan.get("control_id") != PLANNER_CONTROL:
        reasons.append("wrong_control")
    if plan.get("key_layer") not in {"local_api_key", "remote_kms_kek"}:
        reasons.append("unsupported_key_layer")
    if not plan.get("version_labels"):
        reasons.append("missing_symbolic_key_versions")
    if not plan.get("trigger") or not plan.get("next_due"):
        reasons.append("missing_schedule")
    elif date.fromisoformat(plan["next_due"]) < today:
        reasons.append("schedule_overdue")
    if not plan.get("executor") or not plan.get("owner"):
        reasons.append("missing_owner_or_executor")
    if not plan.get("approver"):
        reasons.append("missing_approval")
    elif plan["approver"] == plan.get("executor"):
        reasons.append("approval_not_independent")
    if not plan.get("approval_valid_until"):
        reasons.append("approval_expiry_missing")
    elif date.fromisoformat(plan["approval_valid_until"]) < today:
        reasons.append("approval_expired")
    if not plan.get("change_ref") or not plan.get("rollback_owner"):
        reasons.append("missing_change_or_rollback_reference")
    if not plan.get("migration_method") or not plan.get("retained_reader_window"):
        reasons.append("missing_migration_or_reader_window")

    inventory = plan.get("backup_inventory")
    copies = inventory.get("copies", []) if isinstance(inventory, dict) else []
    if not isinstance(inventory, dict) or not inventory.get("complete") or not copies:
        reasons.append("backup_inventory_incomplete")
    dependent = [copy for copy in copies
                 if copy.get("encrypted_key_label") == plan.get("retiring_version_label")]
    if not dependent:
        reasons.append("no_dependent_backup_copies")
    if any(not item.get("immutable") for item in dependent):
        reasons.append("retention_not_immutable")
    if any(item.get("legal_hold") for item in dependent):
        reasons.append("backup_hold_unresolved")
    retention_dates = [date.fromisoformat(item["retention_until"])
                       for item in dependent if item.get("retention_until")]
    if len(retention_dates) != len(dependent):
        reasons.append("backup_expiry_unknown")

    restore = plan.get("cold_restore")
    dependent_ids = {item["copy_id"] for item in dependent}
    if (not isinstance(restore, dict) or restore.get("status") != "passed"
            or not restore.get("exact_integrity")
            or set(restore.get("covered_copy_ids", [])) != dependent_ids):
        reasons.append("cold_restore_not_verified_for_all_dependent_copies")

    retirement = plan.get("retire_after")
    if not retirement:
        reasons.append("retirement_date_missing")
    elif retention_dates:
        retire_day = date.fromisoformat(retirement)
        minimum_day = max(retention_dates) + timedelta(
            days=plan.get("recovery_allowance_days", 0))
        if retire_day < minimum_day:
            reasons.append("retirement_before_retention_and_recovery_gate")
    return not reasons, reasons


def planner_observations():
    """Exercise fixed synthetic proposals and return sanitized predicates."""
    base = {
        "control_id": PLANNER_CONTROL,
        "key_layer": "local_api_key",
        "version_labels": ["fixture-old-version", "fixture-new-version"],
        "retiring_version_label": "fixture-old-version",
        "trigger": "illustrative fixture cadence: 90 days",
        "next_due": "2026-12-01",
        "owner": "fixture-key-owner",
        "executor": "fixture-operator-a",
        "approver": "fixture-approver-b",
        "approval_valid_until": "2026-12-05",
        "change_ref": "fixture-change-42",
        "rollback_owner": "fixture-recovery-owner",
        "migration_method": "scoped rewrite then authorized reads",
        "retained_reader_window": "until dependent synthetic copies expire",
        "recovery_allowance_days": 7,
        "backup_inventory": {"complete": True, "copies": [
            {"copy_id": "fixture-copy-01", "encrypted_key_label": "fixture-old-version",
             "immutable": True, "retention_until": "2027-01-08", "legal_hold": False},
            {"copy_id": "fixture-copy-02", "encrypted_key_label": "fixture-new-version",
             "immutable": True, "retention_until": "2027-02-01", "legal_hold": False},
        ]},
        "cold_restore": {"status": "passed", "exact_integrity": True,
                         "covered_copy_ids": ["fixture-copy-01"]},
        "retire_after": "2027-01-20",
    }
    before = json.dumps(base, sort_keys=True)
    scenarios = [("complete_future_plan", base, True, [])]

    missing_approval = deepcopy(base)
    missing_approval["approver"] = ""
    scenarios.append(("missing_approval", missing_approval, False, ["missing_approval"]))

    self_approval = deepcopy(base)
    self_approval["approver"] = self_approval["executor"]
    scenarios.append(("self_approval", self_approval, False, ["approval_not_independent"]))

    expired = deepcopy(base)
    expired["approval_valid_until"] = "2026-11-24"
    scenarios.append(("expired_approval", expired, False, ["approval_expired"]))

    overdue = deepcopy(base)
    overdue["next_due"] = "2026-11-24"
    scenarios.append(("overdue_schedule", overdue, False, ["schedule_overdue"]))

    early = deepcopy(base)
    early["retire_after"] = "2027-01-14"
    scenarios.append(("retire_before_retention_plus_recovery", early, False,
                      ["retirement_before_retention_and_recovery_gate"]))

    held = deepcopy(base)
    held["backup_inventory"]["copies"][0]["legal_hold"] = True
    scenarios.append(("unresolved_immutable_hold", held, False, ["backup_hold_unresolved"]))

    incomplete_restore = deepcopy(base)
    incomplete_restore["cold_restore"]["covered_copy_ids"] = []
    scenarios.append(("restore_does_not_cover_old_key_copy", incomplete_restore, False,
                      ["cold_restore_not_verified_for_all_dependent_copies"]))

    outcomes = []
    for name, proposal, expected_accept, expected_reasons in scenarios:
        actual_accept, reasons = planner_decision(proposal)
        outcomes.append({"scenario": name,
                         "matched": actual_accept == expected_accept and reasons == expected_reasons,
                         "accepted": actual_accept, "reason_codes": reasons})
    return {
        "fixture_clock": PLANNER_CLOCK.isoformat(),
        "scenario_count": len(outcomes),
        "matched_scenario_count": sum(bool(item["matched"]) for item in outcomes),
        "scenarios": outcomes,
        "input_unchanged": json.dumps(base, sort_keys=True) == before,
        "all_backup_metadata_synthetic": True,
        "operational_actions": 0,
    }


def key(label):
    return {"name": label, "secret": base64.b64encode(secrets.token_bytes(32)).decode()}


def config_file(lab):
    return lab.kubeconfig.parent / "rotation" / "provider.json"


def write_config(path, keys):
    payload = {"apiVersion": "apiserver.config.k8s.io/v1", "kind": "EncryptionConfiguration",
               "resources": [{"resources": [RESOURCE], "providers": [{"secretbox": {"keys": keys}}]}]}
    incoming = path.with_suffix(".new")
    fd = os.open(incoming, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(payload, stream)
    incoming.replace(path)


def prepare_kind(lab, temporary):
    path = config_file(lab)
    path.parent.mkdir(mode=0o700)
    write_config(path, [key(OLD)])
    kind = temporary / "kind-rotation.yaml"
    kind.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: {json.dumps(str(path.parent))}
        containerPath: {CONFIG_DIR}
        readOnly: true
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        - name: encryption-provider-config
          value: {CONFIG_DIR}/provider.json
      extraVolumes:
        - name: saf-fixture-rotation
          hostPath: {CONFIG_DIR}
          mountPath: {CONFIG_DIR}
          readOnly: true
          pathType: Directory
""")
    return kind


def owned_api(lab, *args):
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
               "--request-timeout=8s", *args]
    try:
        result = subprocess.run(command, env=lab.env, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("The owned rotation probe could not complete")
    if result.returncode:
        lab.block("The owned rotation probe failed without retaining API output")
    return result.stdout


def stored(lab, name):
    exact = f"/registry/{GROUP}/rotationmarkers/{NAMESPACE}/{name}"
    output = owned_api(lab, "-n", "kube-system", "exec", f"etcd-{lab.cluster}-control-plane",
                       "-c", "etcd", "--", "etcdctl", "--endpoints=https://127.0.0.1:2379",
                       "--cacert=/etc/kubernetes/pki/etcd/ca.crt",
                       "--cert=/etc/kubernetes/pki/etcd/server.crt",
                       "--key=/etc/kubernetes/pki/etcd/server.key",
                       "get", exact, "--write-out=json")
    records = json.loads(output).get("kvs", [])
    if len(records) != 1 or base64.b64decode(records[0]["key"]).decode() != exact:
        lab.block("The expected exact owned custom-resource record was missing from etcd")
    value = base64.b64decode(records[0]["value"])
    label = next((name for name in (OLD, NEW) if value.startswith(f"k8s:enc:secretbox:v1:{name}:".encode())), None)
    return {"label": label, "marker_visible": MARKERS[name].encode() in value}


def running_apiserver(lab):
    result = lab.command("docker", "exec", f"{lab.cluster}-control-plane",
                         "crictl", "ps", "--name", "kube-apiserver", "-q", allow_failure=True)
    return result.stdout.split() if result.returncode == 0 else []


def restart_owned_api(lab):
    instances = running_apiserver(lab)
    if len(instances) != 1:
        lab.block("Expected one running API server in the disposable cluster")
    old = instances[0]
    lab.command("docker", "exec", f"{lab.cluster}-control-plane", "crictl", "stop", "--timeout", "1", old)
    deadline = time.monotonic() + 85
    while time.monotonic() < deadline:
        current = running_apiserver(lab)
        if len(current) == 1 and current[0] != old:
            ready = lab.kubectl("get", "--raw=/readyz", timeout=10, allow_failure=True)
            if ready.returncode == 0 and ready.stdout.strip() == "ok":
                return
        time.sleep(1)
    lab.block("The reconfigured disposable API server did not become Ready")


def add_marker(lab, name):
    lab.create({"apiVersion": f"{GROUP}/v1", "kind": "RotationMarker", "metadata": {"name": name},
                "spec": {"marker": MARKERS[name]}})


def readable(lab, name):
    data = owned_api(lab, "-n", NAMESPACE, "get", RESOURCE, name, "-o", "json")
    return json.loads(data)["spec"]["marker"] == MARKERS[name]


def run(lab):
    planner = planner_observations()
    planner_ok = (planner["matched_scenario_count"] == planner["scenario_count"]
                  and planner["input_unchanged"]
                  and planner["all_backup_metadata_synthetic"]
                  and planner["operational_actions"] == 0)
    lab.check("positive", "The synthetic schedule and backup-retirement predicate accepts safe and rejects unsafe proposals",
              planner_ok, planner)
    (lab.evidence / "rotation-schedule-planner-observations.json").write_text(
        json.dumps(planner, indent=2) + "\n")

    lab.create({"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
                "metadata": {"name": RESOURCE}, "spec": {"group": GROUP, "scope": "Namespaced",
                "names": {"plural": "rotationmarkers", "singular": "rotationmarker", "kind": "RotationMarker"},
                "versions": [{"name": "v1", "served": True, "storage": True, "schema": {"openAPIV3Schema": {
                    "type": "object", "properties": {"spec": {"type": "object", "required": ["marker"],
                        "properties": {"marker": {"type": "string"}}}}}}}]}})
    lab.kubectl("wait", "--for=condition=Established", f"crd/{RESOURCE}", "--timeout=45s", timeout=53)
    add_marker(lab, "pre-rotation")
    old_envelope = {"label": OLD, "marker_visible": False}
    new_envelope = {"label": NEW, "marker_visible": False}
    first = stored(lab, "pre-rotation")
    lab.check("red", "The existing record initially requires the old envelope",
              first == old_envelope and readable(lab, "pre-rotation"), first)

    path = config_file(lab)
    new_key = key(NEW)
    old_key = json.loads(path.read_text())["resources"][0]["providers"][0]["secretbox"]["keys"][0]
    write_config(path, [new_key, old_key])
    restart_owned_api(lab)
    add_marker(lab, "post-rotation")
    prior = stored(lab, "pre-rotation")
    fresh = stored(lab, "post-rotation")
    prior_readable = readable(lab, "pre-rotation")
    lab.check("green", "Changing the write key protects new writes and preserves prior reads without rewriting prior data",
              fresh == new_envelope and prior == old_envelope and prior_readable,
              {"new_write": fresh, "old_record": prior, "old_record_readable": prior_readable})

    # Counterfactual rollback before migration: restore the prior key as writer,
    # keeping the newer key available for records already written during rotation.
    write_config(path, [old_key, new_key])
    restart_owned_api(lab)
    add_marker(lab, "rollback-write")
    rollback = stored(lab, "rollback-write")
    rollback_reads = {name: readable(lab, name) for name in ("pre-rotation", "post-rotation", "rollback-write")}
    rollback_envelopes = {name: stored(lab, name) for name in ("pre-rotation", "post-rotation", "rollback-write")}
    rollback_ok = (rollback == old_envelope and all(rollback_reads.values()) and
                   rollback_envelopes == {"pre-rotation": old_envelope,
                                          "post-rotation": new_envelope,
                                          "rollback-write": old_envelope})
    lab.check("positive", "Rollback restores the old write key while retaining reads for both key generations",
              rollback_ok, {"fresh_rollback_write": rollback, "readable": rollback_reads,
                            "stored_envelopes": rollback_envelopes})

    # Resume the forward path with the new writer before exact migration/retirement.
    write_config(path, [new_key, old_key])
    restart_owned_api(lab)
    resumed = {name: readable(lab, name) for name in ("pre-rotation", "post-rotation", "rollback-write")}
    if not all(resumed.values()):
        lab.block("The forward rotation could not resume with all owned records readable")
    del old_key

    lab.kubectl("annotate", RESOURCE, "pre-rotation", "fixture.example/rotation=migrated")
    lab.kubectl("annotate", RESOURCE, "rollback-write", "fixture.example/rotation=migrated")
    migrated = all(stored(lab, name) == new_envelope for name in ("pre-rotation", "rollback-write"))
    if not migrated:
        lab.block("The old fixture must be migrated before retaining only the current read key")
    write_config(path, [new_key])
    del new_key
    restart_owned_api(lab)
    retained = {name: readable(lab, name) and stored(lab, name) == new_envelope for name in MARKERS}
    lab.check("positive", "The API rewrite migrates both old-key records and all three markers remain readable after retirement",
              all(retained.values()), {"rewrite_observed": migrated, "only_current_key_configured": True, "retained": retained})
    (lab.evidence / "etcd-key-rotation-observations.json").write_text(json.dumps({
        "old_envelope": first, "new_write_envelope": fresh, "rollback_write_envelope": rollback,
        "rollback_verified": rollback_ok, "resumed_forward_rotation": resumed,
        "migration_verified": migrated,
        "after_retirement": retained, "provider_kms_tested": False,
    }, indent=2) + "\n")
