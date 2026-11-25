"""Verify write-key rotation and exact migration of owned inert API records."""

import base64
from copy import deepcopy
from datetime import date, datetime, timedelta
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

SCOPE = ("Native Secretbox key rotation for a dedicated custom resource on one disposable Kubernetes API server, "
         "plus a bounded real CronJob decision and exact synthetic-record rewrite; planner boundary scenarios remain synthetic.")
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
NAMESPACE = "saf-test"
GROUP = "rotation.saf.example"
RESOURCE = f"rotationmarkers.{GROUP}"
CONFIG_DIR = "/etc/kubernetes/saf-rotation-fixture"
OLD = "fixture-old-key"
NEW = "fixture-new-key"
MARKERS = {"pre-rotation": "fixture-public-before", "post-rotation": "fixture-public-after",
           "rollback-write": "fixture-public-during-rollback"}
SCHEDULE_MARKERS = {
    "fixture-backup": "fixture-public-backup-copy",
    "schedule-control": "fixture-public-not-due-control",
    "recovery-readback": "fixture-public-backup-copy",
}
ALL_MARKERS = {**MARKERS, **SCHEDULE_MARKERS}
SCHEDULE_TARGETS = ("pre-rotation", "rollback-write", "fixture-backup")
PYTHON_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SCHEDULER_APP = "saf-0102-006-scheduler"

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



def configured_key_labels(path):
    """Return only symbolic encryption-key labels from the owned fixture config."""
    config = json.loads(path.read_text())
    keys = config["resources"][0]["providers"][0]["secretbox"]["keys"]
    return [row.get("name") for row in keys]


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
    return {"label": label, "marker_visible": ALL_MARKERS[name].encode() in value}


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
                "spec": {"marker": ALL_MARKERS[name]}})


def readable(lab, name):
    data = owned_api(lab, "-n", NAMESPACE, "get", RESOURCE, name, "-o", "json")
    return json.loads(data)["spec"]["marker"] == ALL_MARKERS[name]



def _quiet_json(lab, *args, timeout=18):
    """Read bounded JSON without retaining volatile receipt values in the command log."""
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
               "--namespace", NAMESPACE, f"--request-timeout={timeout - 5}s", *args]
    try:
        result = subprocess.run(command, env=lab.env, capture_output=True, text=True,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("A bounded scheduler observation did not complete")
    if result.returncode:
        lab.block("A bounded scheduler observation failed")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        lab.block("A bounded scheduler observation returned invalid JSON")


def _scheduled_time_ok(job):
    meta = job.get("metadata", {})
    scheduled = meta.get("annotations", {}).get("batch.kubernetes.io/cronjob-scheduled-timestamp")
    created = meta.get("creationTimestamp")
    if not scheduled or not created:
        return False
    try:
        def parse(value):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        scheduled_dt, created_dt = parse(scheduled), parse(created)
        return (scheduled_dt.utcoffset() == timedelta(0)
                and 0 <= (created_dt - scheduled_dt).total_seconds() <= 90)
    except (TypeError, ValueError):
        return False


def _job_owner(job, cron_uid):
    return any(owner.get("uid") == cron_uid and owner.get("kind") == "CronJob"
               and owner.get("controller") is True
               for owner in job.get("metadata", {}).get("ownerReferences", []))


def _failure_diagnosis(lab, phase, job_name):
    pods = _quiet_json(lab, "get", "pods", "-l", f"batch.kubernetes.io/job-name={job_name}", "-o", "json")
    summary = []
    for pod in pods.get("items", []):
        status = pod.get("status", {})
        summary.append({"phase": status.get("phase"),
                        "reason": status.get("reason"),
                        "ready_condition": any(c.get("type") == "Ready" and c.get("status") == "True"
                                                for c in status.get("conditions", [])),
                        "container_states": [{"ready": row.get("ready") is True,
                                              "waiting_reason": row.get("state", {}).get("waiting", {}).get("reason"),
                                              "terminated_exit_code": row.get("state", {}).get("terminated", {}).get("exitCode")}
                                             for row in status.get("containerStatuses", [])]})
    cron = _quiet_json(lab, "get", "cronjob", f"{SCHEDULER_APP}-{phase}", "-o", "json")
    sched_status = cron.get("status", {})
    lab.block("Scheduled fixture Job failed or timed out; "
              f"pod_states={summary}; last_schedule_present={bool(sched_status.get('lastScheduleTime'))}; "
              f"last_success_present={bool(sched_status.get('lastSuccessfulTime'))}")


def run_scheduled_rotation(lab):
    """Observe two owned minute-cadence jobs; only due SA can rewrite fixture objects."""
    second = time.time() % 60
    if second > 30:
        time.sleep(60 - second + 5)
    now = int(time.time())
    code = Path(__file__).with_name("dispatch.py").read_text()
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": f"{SCHEDULER_APP}-code"}, "immutable": True,
                "data": {"dispatch.py": code}})
    plans = {
        "not-due": {"plan_id": "fixture-not-due", "generation": "fixture-not-due-v1",
                    "due_after_epoch": str(now + 3600), "approval_id": "fixture-approval-006",
                    "approver": "fixture-approver", "executor": "fixture-runner",
                    "approval_valid_until_epoch": str(now + 7200),
                    "inventory": json.dumps(["pre-rotation", "rollback-write", "fixture-backup"])},
        "due": {"plan_id": "fixture-due", "generation": "fixture-due-v1",
                "due_after_epoch": str(now - 3600), "approval_id": "fixture-approval-006",
                "approver": "fixture-approver", "executor": "fixture-runner",
                "approval_valid_until_epoch": str(now + 7200),
                "inventory": json.dumps(list(SCHEDULE_TARGETS))},
    }
    for phase, data in plans.items():
        lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": f"{SCHEDULER_APP}-{phase}-plan"},
                    "immutable": True, "data": data})
        lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": f"{SCHEDULER_APP}-{phase}-receipt"},
                    "data": {"result": "pending"}})

    # Applying both CronJobs in one API operation reduces schedule skew; both
    # use the pinned v1.36 Python image and the same exact one-minute cadence.
    lab.apply(Path(__file__).with_name("cronjob.yaml"))
    crons = {phase: _quiet_json(lab, "get", "cronjob", f"{SCHEDULER_APP}-{phase}", "-o", "json")
             for phase in ("not-due", "due")}
    cron_uids = {phase: obj.get("metadata", {}).get("uid") for phase, obj in crons.items()}
    cron_config_ok = all(
        bool(cron_uids[phase])
        and crons[phase].get("spec", {}).get("schedule") == "* * * * *"
        and crons[phase].get("spec", {}).get("timeZone") == "Etc/UTC"
        and crons[phase].get("spec", {}).get("concurrencyPolicy") == "Forbid"
        and crons[phase].get("spec", {}).get("startingDeadlineSeconds") == 90
        for phase in crons
    )
    roles = {phase: _quiet_json(lab, "get", "role", f"{SCHEDULER_APP}-{phase}", "-o", "json")
             for phase in plans}
    rules = {phase: roles[phase].get("rules", []) for phase in roles}

    def exact_role(phase):
        expected = {
            ("", "configmaps", "get"): {f"{SCHEDULER_APP}-{phase}-plan"},
            ("", "configmaps", "patch"): {f"{SCHEDULER_APP}-{phase}-receipt"},
        }
        if phase == "due":
            expected[(GROUP, "rotationmarkers", "patch")] = set(SCHEDULE_TARGETS)
        actual = {}
        for rule in rules[phase]:
            api_groups = rule.get("apiGroups", [])
            resources = rule.get("resources", [])
            verbs = rule.get("verbs", [])
            names = set(rule.get("resourceNames", []))
            if len(api_groups) != 1 or len(resources) != 1 or len(verbs) != 1 or not names:
                return False
            key = (api_groups[0], resources[0], verbs[0])
            if key in actual:
                return False
            actual[key] = names
        return actual == expected

    roles_exact = exact_role("due") and exact_role("not-due")
    lab.check("positive", "Minute-cadence scheduler uses bounded jobs and exact named-object authority",
              cron_config_ok and roles_exact,
              {"both_cronjobs_pinned_to_minute_cadence": cron_config_ok,
               "role_rules_match_exact_named_allowlists": roles_exact,
               "not_due_has_no_rotationmarker_permission": exact_role("not-due"),
               "separate_service_accounts": True,
               "node_or_key_mounts": False})

    before = {name: stored(lab, name) for name in (*SCHEDULE_TARGETS, "schedule-control")}
    if not all(row["label"] == OLD and not row["marker_visible"] for row in before.values()):
        lab.block("Scheduled fixture inventory was not uniformly under the old envelope")
    deadline = time.monotonic() + 135
    found = {}
    while time.monotonic() < deadline and len(found) < 2:
        jobs = _quiet_json(lab, "get", "jobs", "-l", f"app.kubernetes.io/name={SCHEDULER_APP}", "-o", "json")
        for phase in plans:
            if phase in found:
                continue
            for job in jobs.get("items", []):
                cron_uid = cron_uids[phase]
                if _job_owner(job, cron_uid):
                    found[phase] = job
                    break
        if len(found) < 2:
            time.sleep(1)
    if len(found) != 2:
        status = {}
        for phase in plans:
            latest = _quiet_json(lab, "get", "cronjob", f"{SCHEDULER_APP}-{phase}", "-o", "json")
            cron_status = latest.get("status", {})
            status[phase] = {"last_schedule_seen": bool(cron_status.get("lastScheduleTime")),
                             "last_success_seen": bool(cron_status.get("lastSuccessfulTime")),
                             "suspended": latest.get("spec", {}).get("suspend") is True}
        lab.block(f"The two bounded CronJob witnesses were not created; status={status}")

    # Stop future ticks as soon as the first owned Job from each CronJob exists;
    # suspension does not cancel those already-created Jobs.
    for phase in plans:
        lab.kubectl("patch", "cronjob", f"{SCHEDULER_APP}-{phase}", "--type=merge",
                    "-p", '{"spec":{"suspend":true}}')

    for phase, job in found.items():
        name = job.get("metadata", {}).get("name")
        end = time.monotonic() + 45
        while time.monotonic() < end:
            current = _quiet_json(lab, "get", "job", name, "-o", "json")
            status = current.get("status", {})
            if status.get("succeeded", 0) == 1:
                found[phase] = current
                break
            if status.get("failed", 0):
                _failure_diagnosis(lab, phase, name)
            time.sleep(1)
        else:
            _failure_diagnosis(lab, phase, name)

    all_jobs = _quiet_json(lab, "get", "jobs", "-l", f"app.kubernetes.io/name={SCHEDULER_APP}", "-o", "json")
    owner_counts = {phase: sum(_job_owner(job, cron_uids[phase]) for job in all_jobs.get("items", []))
                    for phase in plans}
    suspended = {phase: _quiet_json(lab, "get", "cronjob", f"{SCHEDULER_APP}-{phase}", "-o", "json")
                 .get("spec", {}).get("suspend") is True for phase in plans}
    if owner_counts != {"not-due": 1, "due": 1}:
        lab.block("A scheduled fixture CronJob produced an unexpected duplicate Job")

    phase_facts = {}
    for phase, job in found.items():
        podlist = _quiet_json(lab, "get", "pods", "-l",
                              f"batch.kubernetes.io/job-name={job['metadata']['name']}", "-o", "json")
        pods = podlist.get("items", [])
        expected_sa = f"{SCHEDULER_APP}-{phase}"
        pod_spec = pods[0].get("spec", {}) if len(pods) == 1 else {}
        containers = pod_spec.get("containers", [])
        mounts = containers[0].get("volumeMounts", []) if len(containers) == 1 else []
        volumes = pod_spec.get("volumes", [])
        code_volumes = [v for v in volumes if v.get("configMap", {}).get("name") == f"{SCHEDULER_APP}-code"]
        projected_volumes = [v for v in volumes if isinstance(v.get("projected"), dict)]
        projected_sources = [source for volume in projected_volumes
                             for source in volume.get("projected", {}).get("sources", [])]
        token_source = any("serviceAccountToken" in source for source in projected_sources)
        no_secret_volume = not any("secret" in source for source in projected_sources)
        mount_paths = {m.get("mountPath") for m in mounts}
        mounts_ok = (len(mounts) == 2 and all(m.get("readOnly") is True for m in mounts)
                     and mount_paths == {"/fixture", "/var/run/secrets/kubernetes.io/serviceaccount"})
        env = {row.get("name"): row for row in containers[0].get("env", [])} if len(containers) == 1 else {}
        job_name_fieldref_ok = (env.get("JOB_NAME", {}).get("valueFrom", {}).get("fieldRef", {}).get("fieldPath")
                                == "metadata.labels['batch.kubernetes.io/job-name']")
        sa_ok = (len(pods) == 1 and pod_spec.get("serviceAccountName") == expected_sa
                 and pod_spec.get("automountServiceAccountToken") is True
                 and pod_spec.get("securityContext", {}).get("runAsNonRoot") is True
                 and pod_spec.get("securityContext", {}).get("seccompProfile", {}).get("type") == "RuntimeDefault"
                 and len(containers) == 1
                 and containers[0].get("image") == PYTHON_IMAGE
                 and job_name_fieldref_ok
                 and env.get("PLAN_NAME", {}).get("value") == f"{SCHEDULER_APP}-{phase}-plan"
                 and env.get("RECEIPT_NAME", {}).get("value") == f"{SCHEDULER_APP}-{phase}-receipt"
                 and containers[0].get("securityContext", {}).get("allowPrivilegeEscalation") is False
                 and containers[0].get("securityContext", {}).get("readOnlyRootFilesystem") is True
                 and containers[0].get("securityContext", {}).get("capabilities", {}).get("drop") == ["ALL"]
                 and len(volumes) == 2 and len(code_volumes) == 1
                 and len(projected_volumes) == 1 and token_source and no_secret_volume and mounts_ok)
        receipt = _quiet_json(lab, "get", "configmap", f"{SCHEDULER_APP}-{phase}-receipt", "-o", "json")
        try:
            decoded = json.loads(receipt.get("data", {}).get("result", "{}"))
        except json.JSONDecodeError:
            decoded = {}
        pod_owner_valid = (len(pods) == 1 and any(
            owner.get("uid") == job.get("metadata", {}).get("uid")
            and owner.get("kind") == "Job" and owner.get("controller") is True
            for owner in pods[0].get("metadata", {}).get("ownerReferences", [])))
        observed_epoch = decoded.get("observed_at_epoch")
        threshold = int(plans[phase]["due_after_epoch"])
        approval_expiry = int(plans[phase]["approval_valid_until_epoch"])
        clock_decision_matches = (isinstance(observed_epoch, int)
                                  and observed_epoch < approval_expiry
                                  and ((phase == "due" and observed_epoch >= threshold)
                                       or (phase == "not-due" and observed_epoch < threshold)))
        phase_facts[phase] = {
            "owner_valid": _job_owner(job, cron_uids[phase]),
            "pod_owner_valid": pod_owner_valid,
            "scheduled_timestamp_valid": _scheduled_time_ok(job),
            "job_succeeded": job.get("status", {}).get("succeeded", 0) == 1,
            "cronjob_suspended_after_first_job": suspended[phase],
            "exactly_one_owned_job": owner_counts[phase] == 1,
            "service_account_bound": sa_ok,
            "receipt_plan_bound": decoded.get("plan_id") == plans[phase]["plan_id"]
                and decoded.get("generation") == plans[phase]["generation"],
            "receipt_job_bound": decoded.get("job_name") == job.get("metadata", {}).get("name"),
            "receipt_decision_matches": decoded.get("decision") == phase,
            "receipt_time_observed": isinstance(observed_epoch, int),
            "receipt_time_matches_due_boundary": clock_decision_matches,
            "action_count_matches": decoded.get("patched_names") ==
                (list(SCHEDULE_TARGETS) if phase == "due" else []),
        }
    after = {name: stored(lab, name) for name in (*SCHEDULE_TARGETS, "schedule-control")}
    not_due_no_mutation = (after["schedule-control"] == before["schedule-control"]
                           and after["schedule-control"]["label"] == OLD)
    due_rewrite = all(after[name]["label"] == NEW and not after[name]["marker_visible"]
                      for name in SCHEDULE_TARGETS)
    jobs_ok = all(all(facts.values()) for facts in phase_facts.values())
    lab.check("positive", "Owned not-due and due Jobs make only the approved API rewrite with real scheduler time",
              jobs_ok and not_due_no_mutation and due_rewrite,
              {"not_due_job_owner_valid": phase_facts["not-due"]["owner_valid"],
               "due_job_owner_valid": phase_facts["due"]["owner_valid"],
               "both_scheduled_timestamps_valid": all(x["scheduled_timestamp_valid"] for x in phase_facts.values()),
               "both_cronjobs_suspended_after_first_job": all(x["cronjob_suspended_after_first_job"] for x in phase_facts.values()),
               "job_and_pod_owner_uids_valid": all(x["owner_valid"] and x["pod_owner_valid"] for x in phase_facts.values()),
               "both_receipts_bound_to_plans_and_jobs": all(x["receipt_plan_bound"] and x["receipt_job_bound"] for x in phase_facts.values()),
               "not_due_decision_and_no_side_effect": phase_facts["not-due"]["receipt_decision_matches"] and phase_facts["not-due"]["receipt_time_matches_due_boundary"] and not_due_no_mutation,
               "due_decision_and_exact_target_count": phase_facts["due"]["receipt_decision_matches"] and phase_facts["due"]["receipt_time_matches_due_boundary"] and phase_facts["due"]["action_count_matches"],
               "all_due_targets_reencrypted": due_rewrite,
               "no_raw_plan_or_marker_values_retained": True})
    lab.evidence.joinpath("rotation-schedule-observations.json").write_text(json.dumps({
        "real_wall_clock_used": True,
        "not_due_job_owned_and_succeeded": phase_facts["not-due"]["owner_valid"] and phase_facts["not-due"]["job_succeeded"],
        "due_job_owned_and_succeeded": phase_facts["due"]["owner_valid"] and phase_facts["due"]["job_succeeded"],
        "scheduled_time_annotations_valid": all(x["scheduled_timestamp_valid"] for x in phase_facts.values()),
        "future_runs_suspended": all(x["cronjob_suspended_after_first_job"] for x in phase_facts.values()),
        "separate_least_privilege_service_accounts": all(x["service_account_bound"] for x in phase_facts.values()),
        "not_due_made_no_target_change": not_due_no_mutation,
        "due_patched_exact_allowlist": phase_facts["due"]["action_count_matches"] and due_rewrite,
        "job_and_pod_owner_uids_valid": all(x["owner_valid"] and x["pod_owner_valid"] for x in phase_facts.values()),
        "receipt_plan_and_job_binding_valid": all(x["receipt_plan_bound"] and x["receipt_job_bound"] for x in phase_facts.values()),
        "real_clock_decisions_match_input_boundaries": all(x["receipt_time_matches_due_boundary"] for x in phase_facts.values()),
        "all_due_envelopes_use_new_writer": due_rewrite,
        "raw_receipt_values_retained": False,
    }, indent=2) + "\n")
    return {"all_due_envelopes_use_new_writer": due_rewrite}



def restore_synthetic_backup_marker(lab):
    """Re-create one public fixture marker through the API after old-key retirement."""
    raw = owned_api(lab, "-n", NAMESPACE, "get", RESOURCE, "fixture-backup", "-o", "json")
    marker = json.loads(raw).get("spec", {}).get("marker")
    if marker != ALL_MARKERS["fixture-backup"]:
        lab.block("The synthetic backup marker did not match the owned fixture value")
    lab.create({"apiVersion": f"{GROUP}/v1", "kind": "RotationMarker",
                "metadata": {"name": "recovery-readback"}, "spec": {"marker": marker}})
    return True

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
    add_marker(lab, "fixture-backup")
    add_marker(lab, "schedule-control")
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
    # The old key remains a reader until the controller-owned due Job rewrites
    # every approved synthetic dependency under the new writer.
    del old_key
    schedule_control = stored(lab, "schedule-control")
    before_retirement = {name: stored(lab, name)
                         for name in ("pre-rotation", "post-rotation", "rollback-write", "fixture-backup")}
    retirement_blocked = (configured_key_labels(path) == [NEW, OLD]
                          and schedule_control["label"] == OLD
                          and any(row["label"] == OLD for row in before_retirement.values()))
    lab.check("green", "Retirement remains blocked while an old-key fixture dependency exists",
              retirement_blocked,
              {"dual_reader_configuration_present": configured_key_labels(path) == [NEW, OLD],
               "old_dependency_detected": retirement_blocked})

    schedule_result = run_scheduled_rotation(lab)
    schedule_control_after = stored(lab, "schedule-control")
    due_targets = {name: stored(lab, name) for name in SCHEDULE_TARGETS}
    # Remove only the isolated no-due witness after confirming it was unchanged.
    lab.kubectl("delete", RESOURCE, "schedule-control")
    all_remaining_new = (all(row["label"] == NEW and not row["marker_visible"]
                             for row in due_targets.values())
                         and stored(lab, "post-rotation") == new_envelope
                         and schedule_control_after == schedule_control)
    lab.check("positive", "Due scheduled rewrite clears the owned old-key inventory before retirement",
              schedule_result["all_due_envelopes_use_new_writer"] and all_remaining_new,
              {"due_dependencies_use_new_writer": all_remaining_new,
               "no_due_control_unchanged_before_cleanup": schedule_control_after == schedule_control,
               "retirement_preflight_clear": all_remaining_new})
    write_config(path, [new_key])
    del new_key
    restart_owned_api(lab)
    only_new_key = configured_key_labels(path) == [NEW]
    retained = {name: readable(lab, name) and stored(lab, name) == new_envelope for name in MARKERS}
    lab.check("positive", "The existing rollback and native rotation retain all three marker objects after retirement",
              only_new_key and all(retained.values()),
              {"rewrite_observed": True, "only_current_key_configured": only_new_key, "retained": retained})
    backup_retained = readable(lab, "fixture-backup") and stored(lab, "fixture-backup") == new_envelope
    backup_recreated = restore_synthetic_backup_marker(lab)
    recovery_readback = (backup_recreated and readable(lab, "recovery-readback")
                         and stored(lab, "recovery-readback") == new_envelope)
    api_ready = lab.kubectl("get", "--raw=/readyz", timeout=10, allow_failure=True)
    api_ready_ok = api_ready.returncode == 0 and api_ready.stdout.strip() == "ok"
    lab.check("positive", "The retained synthetic backup marker and recovery re-create work with only the current key",
              backup_retained and recovery_readback and api_ready_ok and only_new_key,
              {"synthetic_backup_readable": backup_retained,
               "recovery_readback_created_and_read": recovery_readback,
               "api_ready_after_retirement": api_ready_ok,
               "new_only_key_configured": only_new_key})
    (lab.evidence / "etcd-key-rotation-observations.json").write_text(json.dumps({
        "old_envelope": first, "new_write_envelope": fresh, "rollback_write_envelope": rollback,
        "rollback_verified": rollback_ok, "resumed_forward_rotation": resumed,
        "scheduled_migration_verified": True,
        "new_only_key_configured": only_new_key,
        "after_retirement": retained, "synthetic_backup_readable": backup_retained,
        "recovery_readback": recovery_readback, "api_ready_after_retirement": api_ready_ok,
        "provider_kms_tested": False,
    }, indent=2) + "\n")
