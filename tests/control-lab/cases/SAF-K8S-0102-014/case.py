"""Exercise kubeadm-managed stacked-etcd leaf certificate renewal in disposable Kind."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import time


SCOPE = (
    "One disposable Kind v1.36.1 control-plane node using kubeadm's local PKI and stacked etcd. "
    "A pure planner evaluates each public leaf lifetime under explicit synthetic expiry-offset "
    "timestamps and selects the existing server/client/peer command order without changing host time. "
    "The case detects a partial renewal, completes kubeadm "
    "certificate renewal, restarts the etcd and kube-apiserver static Pods, compares public "
    "certificate receipts before/after and live etcd server/peer receipts to renewed files, "
    "then writes and reads back a synthetic ConfigMap through the Kubernetes API. "
    "A namespaced CronJob makes real not-due and due invocations against the exact public leaf inventory, "
    "using explicitly labeled synthetic expiry-offset decision instants; its Pod cannot renew or restart. "
    "No private key, token, secret value, external PKI, multi-member behavior, real-clock lead-window "
    "scheduling, or production cluster is exercised."
)

NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
CERTS = {
    "etcd/server": "/etc/kubernetes/pki/etcd/server.crt",
    "etcd/peer": "/etc/kubernetes/pki/etcd/peer.crt",
    "apiserver-etcd-client": "/etc/kubernetes/pki/apiserver-etcd-client.crt",
}
EXPECTED_EKU = {
    "etcd/server": "TLS Web Server Authentication,TLS Web Client Authentication",
    "etcd/peer": "TLS Web Server Authentication,TLS Web Client Authentication",
    "apiserver-etcd-client": "TLS Web Client Authentication",
}
RAW_FILE = "certificate-rotation.raw.json"
LEAD_SECONDS = 30 * 24 * 60 * 60  # Example fixture policy, not a Kubernetes default.
ROTATION_ORDER = ("etcd/server", "apiserver-etcd-client", "etcd/peer")
RENEW_TARGETS = {
    "etcd/server": "etcd-server",
    "etcd/peer": "etcd-peer",
    "apiserver-etcd-client": "apiserver-etcd-client",
}
DELIBERATE_OMISSION = "etcd/peer"
SCHEDULE_INPUT = "saf-0102-014-schedule-input"
SCHEDULE_NOT_DUE = "saf-0102-014-schedule-not-due"
SCHEDULE_DUE = "saf-0102-014-schedule-due"
SCHEDULER = "saf-0102-014-scheduler"
SCHEDULE_CLOCK_BASIS = "synthetic_expiry_offsets_only"


def node(lab, script, *, timeout=30):
    return lab.command("docker", "exec", f"{lab.cluster}-control-plane", "sh", "-ceu", script,
                       timeout=timeout)


def parse_receipt(name, output):
    fingerprint = re.search(r"(?:sha256 )?Fingerprint=([0-9A-Fa-f:]+)", output)
    serial = re.search(r"^serial=([0-9A-Fa-f]+)$", output, re.M)
    start = re.search(r"^notBefore=(.+)$", output, re.M)
    end = re.search(r"^notAfter=(.+)$", output, re.M)
    if not all((fingerprint, serial, start, end)):
        raise RuntimeError(f"Could not parse public certificate receipt for {name}")
    extensions = {"keyUsage": "", "extendedKeyUsage": ""}
    active = None
    for line in output.splitlines():
        if line.strip().startswith("X509v3 Key Usage:"):
            active = "keyUsage"
        elif line.strip().startswith("X509v3 Extended Key Usage:"):
            active = "extendedKeyUsage"
        elif line.strip().startswith("X509v3 "):
            active = None
        elif active and line.strip():
            extensions[active] += line.strip()
    if not all(extensions.values()):
        raise RuntimeError(f"Certificate usage flags missing for {name}")
    return {
        "class": name,
        "sha256_fingerprint": fingerprint.group(1).replace(":", "").lower(),
        "serial": serial.group(1).lower().lstrip("0") or "0",
        "not_before": start.group(1),
        "not_after": end.group(1),
        "key_usage": extensions["keyUsage"].replace(", ", ","),
        "extended_key_usage": extensions["extendedKeyUsage"].replace(", ", ","),
    }


def public_receipts(lab):
    receipts = {}
    for name, path in CERTS.items():
        # openssl x509 reads only the public certificate; no key file is opened or emitted.
        output = node(
            lab,
            f"openssl x509 -in {shlex.quote(path)} -noout -fingerprint -sha256 "
            "-serial -startdate -enddate -ext keyUsage,extendedKeyUsage",
        ).stdout
        receipts[name] = parse_receipt(name, output)
    return receipts


def expiry_epoch(value):
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    ).timestamp()


def plan_due_roles(receipts, now_epoch, lead_seconds):
    """Pure decision helper; now_epoch is explicit and may be synthetic."""
    due = []
    for role in ROTATION_ORDER:
        receipt = receipts[role]
        start = expiry_epoch(receipt["not_before"])
        expiry = expiry_epoch(receipt["not_after"])
        if start <= now_epoch < expiry and expiry - now_epoch <= lead_seconds:
            due.append(role)
    return due


def preexpiry_decision_evidence(receipts):
    """Exercise deterministic window edges without reading or changing host time."""
    expiries = {role: expiry_epoch(receipts[role]["not_after"]) for role in ROTATION_ORDER}
    starts = {role: expiry_epoch(receipts[role]["not_before"]) for role in ROTATION_ORDER}
    edge_results = {}
    for role in ROTATION_ORDER:
        outside_now = expiries[role] - LEAD_SECONDS - 1
        boundary_now = expiries[role] - LEAD_SECONDS
        edge_results[role] = {
            "outside_window_excludes_role": role not in plan_due_roles(
                receipts, outside_now, LEAD_SECONDS
            ),
            "at_boundary_includes_role": role in plan_due_roles(
                receipts, boundary_now, LEAD_SECONDS
            ),
            "outside_time_within_leaf_lifetime": starts[role] <= outside_now < expiries[role],
            "boundary_time_within_leaf_lifetime": starts[role] <= boundary_now < expiries[role],
            "expired_role_outside_planned_window": role not in plan_due_roles(
                receipts, expiries[role], LEAD_SECONDS),
        }

    all_due_now = max(expiries.values()) - LEAD_SECONDS
    all_due = plan_due_roles(receipts, all_due_now, LEAD_SECONDS)
    all_due_before_expiry = all_due_now < min(expiries.values())
    all_due_after_not_before = all_due_now >= max(starts.values())
    checks = {
        "clock_basis_is_synthetic_expiry_offset": True,
        "all_role_boundary_checks_pass": all(
            all(row.values()) for row in edge_results.values()
        ),
        "all_roles_selected_in_declared_order": tuple(all_due) == ROTATION_ORDER,
        "all_due_decision_precedes_every_expiry": all_due_before_expiry,
        "all_due_decision_follows_every_not_before": all_due_after_not_before,
        "due_plan_splits_into_existing_command_phases": (
            tuple(role for role in all_due if role != DELIBERATE_OMISSION)
            == ("etcd/server", "apiserver-etcd-client")
            and tuple(role for role in all_due if role == DELIBERATE_OMISSION)
            == ("etcd/peer",)
        ),
    }
    return all_due, {"lead_seconds": LEAD_SECONDS, **checks, "role_boundaries": edge_results}


def run_scheduled_decisions(lab, receipts, expected_due):
    """Use real CronJob ticks with explicitly synthetic expiry decision instants."""
    directory = Path(__file__).resolve().parent
    roles = [{"role": role,
              "sha256_fingerprint": receipts[role]["sha256_fingerprint"],
              "not_before_epoch": int(expiry_epoch(receipts[role]["not_before"])),
              "not_after_epoch": int(expiry_epoch(receipts[role]["not_after"]))}
             for role in ROTATION_ORDER]
    expiries = [row["not_after_epoch"] for row in roles]
    outside_epoch = min(expiries) - LEAD_SECONDS - 1
    due_epoch = max(expiries) - LEAD_SECONDS
    expected_outside = plan_due_roles(receipts, outside_epoch, LEAD_SECONDS)
    expected_due_at = plan_due_roles(receipts, due_epoch, LEAD_SECONDS)
    if expected_outside or tuple(expected_due_at) != tuple(expected_due):
        lab.block("Synthetic scheduler decision instants do not match the native role planner")

    receipts_names = (SCHEDULE_NOT_DUE, SCHEDULE_DUE)
    initial_input = {"inventory_json": json.dumps(roles, sort_keys=True, separators=(",", ":")),
                     "lead_seconds": str(LEAD_SECONDS),
                     "decision_at_epoch": str(outside_epoch),
                     "clock_basis": SCHEDULE_CLOCK_BASIS,
                     "receipt_name": SCHEDULE_NOT_DUE}
    resources = [
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": SCHEDULE_INPUT},
         "data": initial_input},
        *[{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
           "data": {"decision": "pending"}} for name in receipts_names],
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": "saf-0102-014-scheduler-code"},
         "data": {"dispatch.py": (directory / "dispatch.py").read_text(encoding="utf-8")}},
    ]
    created = []
    selector = f"app.kubernetes.io/name={SCHEDULER}"
    owner_uid = None

    def read_receipt(name):
        response = lab.kubectl("get", "configmap", name, "-o", "json")
        return json.loads(response.stdout).get("data", {})

    def wait_owned_receipt(name, decision):
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline:
            data = read_receipt(name)
            if data.get("decision") == decision and data.get("job_name"):
                jobs = json.loads(lab.kubectl(
                    "get", "jobs", "-l", selector, "-o", "json").stdout)["items"]
                owners = [job for job in jobs
                          if job["metadata"].get("name") == data["job_name"]
                          and job.get("status", {}).get("succeeded") == 1
                          and any(owner.get("kind") == "CronJob"
                                  and owner.get("name") == SCHEDULER
                                  and owner.get("uid") == owner_uid
                                  and owner.get("controller") is True
                                  for owner in job["metadata"].get("ownerReferences", []))]
                if len(owners) == 1:
                    return data, owners[0]
            time.sleep(2)
        lab.block(f"Timed out waiting for CronJob-owned {decision} receipt")

    try:
        for resource in resources:
            lab.create(resource)
            created.append(("configmap", resource["metadata"]["name"]))
        created.extend((kind, name) for kind, name in (
            ("serviceaccount", SCHEDULER), ("role", SCHEDULER),
            ("rolebinding", SCHEDULER), ("cronjob", SCHEDULER)))
        lab.apply(directory / "cronjob.yaml")

        role = json.loads(lab.kubectl("get", "role", SCHEDULER, "-o", "json").stdout)
        actual_rules = sorted((tuple(row.get("apiGroups", [])),
                               tuple(row.get("resources", [])),
                               tuple(sorted(row.get("resourceNames", []))),
                               tuple(row.get("verbs", []))) for row in role.get("rules", []))
        expected_rules = sorted([
            (("",), ("configmaps",), (SCHEDULE_INPUT,), ("get",)),
            (("",), ("configmaps",), tuple(sorted(receipts_names)), ("patch",)),
        ])
        lab.check("positive", "Scheduled identity has only named public-input and receipt ConfigMap permissions",
                  actual_rules == expected_rules,
                  {"exact_named_rbac": actual_rules == expected_rules,
                   "rule_count": len(actual_rules)})

        cronjob = json.loads(lab.kubectl("get", "cronjob", SCHEDULER, "-o", "json").stdout)
        owner_uid = cronjob["metadata"]["uid"]
        subject = f"system:serviceaccount:saf-test:{SCHEDULER}"
        permission_checks = (
            ("get", f"configmaps/{SCHEDULE_INPUT}", "yes"),
            ("patch", f"configmaps/{SCHEDULE_DUE}", "yes"),
            ("patch", f"configmaps/{SCHEDULE_NOT_DUE}", "yes"),
            ("patch", f"configmaps/{SCHEDULE_INPUT}", "no"),
            ("get", "secrets", "no"), ("create", "pods", "no"), ("get", "nodes", "no"),
        )
        decisions_match = all(
            lab.kubectl("auth", "can-i", verb, resource, "--as", subject,
                        "--as-group=system:serviceaccounts",
                        "--as-group=system:serviceaccounts:saf-test",
                        "--as-group=system:authenticated", timeout=15,
                        allow_failure=True).stdout.strip() == expected
            for verb, resource, expected in permission_checks
        )
        lab.check("positive", "Scheduled identity cannot read credentials or access nodes or Pods",
                  decisions_match,
                  {"named_configmap_permissions_only": decisions_match})

        pod = cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        container = pod["containers"][0]
        job_template = cronjob["spec"]["jobTemplate"]
        job_name_env = next((entry for entry in container.get("env", [])
                             if entry.get("name") == "JOB_NAME"), {})
        confined = (pod.get("serviceAccountName") == SCHEDULER
                    and job_template.get("metadata", {}).get("labels", {}).get(
                        "app.kubernetes.io/name") == SCHEDULER
                    and job_name_env.get("valueFrom", {}).get("fieldRef", {}).get("fieldPath")
                    == "metadata.labels['batch.kubernetes.io/job-name']"
                    and not pod.get("hostNetwork", False) and not pod.get("hostPID", False)
                    and not pod.get("hostIPC", False)
                    and not any("hostPath" in volume for volume in pod.get("volumes", []))
                    and container.get("securityContext", {}).get("readOnlyRootFilesystem") is True
                    and container.get("securityContext", {}).get("allowPrivilegeEscalation") is False
                    and not any("kubeconfig" in mount.get("mountPath", "")
                                or "/etc/kubernetes/pki" in mount.get("mountPath", "")
                                for mount in container.get("volumeMounts", [])))
        lab.check("positive", "The CronJob uses stable Job labels and has no host or certificate access",
                  confined, {"bounded_pod_and_job_identity": confined})

        first, first_job = wait_owned_receipt(SCHEDULE_NOT_DUE, "not_due")
        digest = hashlib.sha256(json.dumps(roles, sort_keys=True,
                                          separators=(",", ":")).encode()).hexdigest()
        receipt_keys = {"decision", "selected_roles_json", "selected_receipts_json",
                        "inventory_sha256", "lead_seconds", "decision_at_epoch",
                        "clock_basis", "observed_at_epoch", "job_name", "request_id"}
        first_ok = (set(first) == receipt_keys
                    and first.get("inventory_sha256") == digest
                    and first.get("selected_roles_json") == "[]"
                    and first.get("selected_receipts_json") == "[]"
                    and int(first.get("lead_seconds", "-1")) == LEAD_SECONDS
                    and int(first.get("decision_at_epoch", "-1")) == outside_epoch
                    and first.get("clock_basis") == SCHEDULE_CLOCK_BASIS
                    and int(first.get("observed_at_epoch", "0")) > 0
                    and first.get("job_name") == first_job["metadata"]["name"]
                    and first.get("request_id") == "")
        lab.check("positive", "A real CronJob-owned Job records not-due for the exact public role inventory",
                  first_ok, {"job_owned_by_current_cronjob_uid": True,
                             "exact_public_inventory_bound": first_ok,
                             "clock_basis": first.get("clock_basis")})

        lab.kubectl("patch", "cronjob", SCHEDULER, "--type=merge", "-p",
                    '{"spec":{"suspend":true}}', timeout=15)
        due_input = {**initial_input, "decision_at_epoch": str(due_epoch),
                     "receipt_name": SCHEDULE_DUE}
        lab.kubectl("patch", "configmap", SCHEDULE_INPUT, "--type=merge", "-p",
                    json.dumps({"data": due_input}, separators=(",", ":")), timeout=15)
        suspended = json.loads(lab.kubectl("get", "cronjob", SCHEDULER, "-o", "json").stdout)
        if suspended.get("spec", {}).get("suspend") is not True:
            lab.block("Could not suspend scheduling while staging the due role receipt")
        lab.kubectl("patch", "cronjob", SCHEDULER, "--type=merge", "-p",
                    '{"spec":{"suspend":false}}', timeout=15)

        second, second_job = wait_owned_receipt(SCHEDULE_DUE, "renewal_request")
        selected_receipts = [{"role": row["role"],
                              "sha256_fingerprint": row["sha256_fingerprint"],
                              "not_before_epoch": row["not_before_epoch"],
                              "not_after_epoch": row["not_after_epoch"]}
                             for row in roles if row["role"] in expected_due]
        stable_second = (set(second) == receipt_keys
                         and second.get("inventory_sha256") == digest
                         and json.loads(second.get("selected_roles_json", "null")) == expected_due
                         and json.loads(second.get("selected_receipts_json", "null")) == selected_receipts
                         and int(second.get("lead_seconds", "-1")) == LEAD_SECONDS
                         and int(second.get("decision_at_epoch", "-1")) == due_epoch
                         and second.get("clock_basis") == SCHEDULE_CLOCK_BASIS
                         and int(second.get("observed_at_epoch", "0")) > 0
                         and second.get("job_name") == second_job["metadata"]["name"]
                         and second.get("job_name") != first.get("job_name")
                         and second.get("request_id") == digest + ":" + str(due_epoch))
        lab.check("positive", "A distinct CronJob-owned Job requests the exact native all-role plan at synthetic due boundary",
                  stable_second,
                  {"exact_ordered_roles_and_fingerprints": stable_second,
                   "distinct_controller_job": second.get("job_name") != first.get("job_name"),
                   "clock_basis": second.get("clock_basis")})

        jobs = json.loads(lab.kubectl("get", "jobs", "-l", selector, "-o", "json").stdout)["items"]
        successful = {job["metadata"]["name"] for job in jobs
                      if job.get("status", {}).get("succeeded") == 1
                      and any(owner.get("kind") == "CronJob" and owner.get("name") == SCHEDULER
                              and owner.get("uid") == owner_uid and owner.get("controller") is True
                              for owner in job["metadata"].get("ownerReferences", []))}
        exactly_two = successful == {first["job_name"], second["job_name"]}
        lab.check("positive", "Exactly two successful Jobs owned by this CronJob produced the two receipts",
                  exactly_two, {"exactly_two_successful_controller_jobs": exactly_two})
        (lab.evidence / "scheduled-role-plan-observations.json").write_text(json.dumps({
            "clock_basis": SCHEDULE_CLOCK_BASIS,
            "lead_seconds": LEAD_SECONDS,
            "public_inventory_sha256": digest,
            "not_due": first,
            "due": second,
            "successful_controller_jobs": sorted(successful),
            "host_clock_changed": False,
        }, indent=2, sort_keys=True) + "\n")
        return json.loads(second["selected_roles_json"])
    finally:
        lab.kubectl("delete", "cronjob", SCHEDULER, "--ignore-not-found=true",
                    timeout=15, allow_failure=True)
        for kind, name in reversed(created):
            if kind == "cronjob":
                continue
            lab.kubectl("delete", kind, name, "--ignore-not-found=true",
                        timeout=15, allow_failure=True)


def active_fingerprint(lab, address, port, client_cert, client_key):
    command = (
        "timeout 8 openssl s_client "
        f"-connect {shlex.quote(address)}:{port} -verify_ip {shlex.quote(address)} "
        "-verify_return_error -CAfile /etc/kubernetes/pki/etcd/ca.crt "
        f"-cert {client_cert} -key {client_key} -showcerts </dev/null 2>/dev/null "
        "| openssl x509 -noout -fingerprint -sha256"
    )
    result = node(lab, command, timeout=15)
    match = re.search(r"(?:sha256 )?Fingerprint=([0-9A-Fa-f:]+)", result.stdout)
    if not match:
        raise RuntimeError(f"No active TLS certificate observed on etcd port {port}")
    return match.group(1).replace(":", "").lower()


def restart_static_pod(lab, manifest, container_name):
    script = r'''manifest="$1"
name="$2"
held="/tmp/saf-rotation-$(basename "$manifest").held"
test -f "$manifest"
test ! -e "$held"
before="$(crictl ps --name "$name" -q | head -n 1)"
test -n "$before"
restore() { if test -f "$held"; then mv "$held" "$manifest"; fi; }
trap restore EXIT HUP INT TERM
mv "$manifest" "$held"
gone=0
i=0
while test "$i" -lt 45; do
  if test -z "$(crictl ps --name "$name" -q | head -n 1)"; then gone=1; break; fi
  sleep 1
  i=$((i + 1))
done
test "$gone" -eq 1
mv "$held" "$manifest"
trap - EXIT HUP INT TERM
i=0
while test "$i" -lt 90; do
  after="$(crictl ps --name "$name" -q | head -n 1)"
  if test -n "$after" && test "$after" != "$before"; then
    printf 'restarted\n'
    exit 0
  fi
  sleep 1
  i=$((i + 1))
done
exit 1'''
    result = lab.command(
        "docker", "exec", f"{lab.cluster}-control-plane", "sh", "-ceu", script,
        "sh", manifest, container_name,
        timeout=150,
    )
    return "restarted" in result.stdout


def record_raw(lab, observations):
    (lab.evidence / RAW_FILE).write_text(json.dumps(observations, indent=2, sort_keys=True) + "\n")


def run(lab):
    # Ensure the harness really supplied the one-node, exact-version target expected here.
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    if version != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {version}")
    node_version = node(lab, "kubeadm version -o short").stdout.strip()
    if node_version != "v1.36.1":
        lab.block(f"Expected kubeadm v1.36.1, got {node_version}")
    ready_nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    if len(ready_nodes) != 1 or ready_nodes[0]["status"]["nodeInfo"]["kubeletVersion"] != version:
        lab.block("Expected exactly one ready-version node in the disposable Kind cluster")

    before = public_receipts(lab)
    required = set(CERTS)
    planned_roles, planner_evidence = preexpiry_decision_evidence(before)
    planner_ok = all(value for key, value in planner_evidence.items()
                     if key not in {"lead_seconds", "role_boundaries"}) and all(
                         all(row.values()) for row in planner_evidence["role_boundaries"].values()
                     )
    lab.check(
        "positive",
        "Synthetic pre-expiry decisions select each exact public leaf at its boundary and all roles before expiry",
        planner_ok,
        {key: value for key, value in planner_evidence.items() if key != "role_boundaries"}
        | {"role_boundary_predicates": planner_evidence["role_boundaries"]},
    )
    if not planner_ok or set(planned_roles) != required:
        lab.block("The synthetic pre-expiry planner did not select exactly the required roles")

    scheduled_roles = run_scheduled_decisions(lab, before, planned_roles)
    schedule_matches = tuple(scheduled_roles) == tuple(planned_roles)
    lab.check("positive", "Scheduled controller receipt matches the existing native all-role plan",
              schedule_matches,
              {"scheduled_order_matches_native_order": schedule_matches,
               "selected_role_count": len(scheduled_roles),
               "clock_basis": SCHEDULE_CLOCK_BASIS})
    if not schedule_matches:
        lab.block("The scheduled due role receipt differs from the native certificate plan")
    planned_roles = scheduled_roles

    marker = {"apiVersion": "v1", "kind": "ConfigMap",
              "metadata": {"name": "cert-rotation-before"},
              "data": {"marker": "stored-before-renewal"}}
    lab.create(marker)

    # Detect the coverage gap without putting partially renewed files in service.
    initial_roles = [role for role in planned_roles if role != DELIBERATE_OMISSION]
    renewal_commands = " && ".join(
        f"kubeadm certs renew {RENEW_TARGETS[role]}" for role in initial_roles
    )
    first = node(lab, renewal_commands, timeout=90)
    incomplete = public_receipts(lab)
    unchanged = sorted(name for name in required if
                       before[name]["sha256_fingerprint"] == incomplete[name]["sha256_fingerprint"])
    lab.check(
        "red",
        "The live certificate audit detects that the partial renewal omitted the peer class",
        unchanged == ["etcd/peer"],
        {"required_classes": sorted(required), "unchanged_after_partial_renewal": unchanged},
    )
    remaining_roles = [role for role in planned_roles if role not in initial_roles]
    remaining_commands = " && ".join(
        f"kubeadm certs renew {RENEW_TARGETS[role]}" for role in remaining_roles
    )
    renewal = node(lab, remaining_commands, timeout=90)
    after = public_receipts(lab)
    now = time.time()
    per_class = {}
    for name in sorted(required):
        old, new = before[name], after[name]
        per_class[name] = {
            "fingerprint_changed": old["sha256_fingerprint"] != new["sha256_fingerprint"],
            "serial_changed": old["serial"] != new["serial"],
            "expiry_extended": expiry_epoch(new["not_after"]) > expiry_epoch(old["not_after"]),
            "new_certificate_current": expiry_epoch(new["not_before"]) <= now < expiry_epoch(new["not_after"]),
            "usage_flags_preserved": (old["key_usage"], old["extended_key_usage"])
            == (new["key_usage"], new["extended_key_usage"]),
            "extended_key_usage_matches_role": set(part.strip() for part in new["extended_key_usage"].split(",")) == set(EXPECTED_EKU[name].split(",")),
        }
    disk_comparison_ok = all(all(result.values()) for result in per_class.values())
    if set(after) != required or set(before) != required:
        disk_comparison_ok = False
    lab.check(
        "green",
        "The completed kubeadm renewal replaces all three public leaf receipts and preserves their usage flags",
        disk_comparison_ok,
        {"all_required_classes_compared": set(after) == required and set(before) == required,
         "all_fingerprints_and_serials_changed": all(x["fingerprint_changed"] and x["serial_changed"] for x in per_class.values()),
         "all_expiries_extended_and_current": all(x["expiry_extended"] and x["new_certificate_current"] for x in per_class.values()),
         "all_usage_flags_preserved": all(x["usage_flags_preserved"] for x in per_class.values()),
         "all_extended_key_usages_match_roles": all(x["extended_key_usage_matches_role"] for x in per_class.values()),
         "raw_evidence_file": RAW_FILE},
    )

    etcd_restarted = restart_static_pod(lab, "/etc/kubernetes/manifests/etcd.yaml", "etcd")
    apiserver_restarted = restart_static_pod(
        lab, "/etc/kubernetes/manifests/kube-apiserver.yaml", "kube-apiserver"
    )
    deadline = time.monotonic() + 65
    while time.monotonic() < deadline:
        ready = lab.kubectl("get", "--raw=/readyz", timeout=10, allow_failure=True)
        if ready.returncode == 0 and ready.stdout.strip() == "ok":
            break
        time.sleep(1)
    else:
        lab.block("Restarted control plane did not become Ready")

    node_ip = next(value["address"] for value in ready_nodes[0]["status"]["addresses"]
                   if value["type"] == "InternalIP")

    active_server = active_fingerprint(
        lab, "127.0.0.1", 2379, "/etc/kubernetes/pki/etcd/healthcheck-client.crt",
        "/etc/kubernetes/pki/etcd/healthcheck-client.key",
    )
    active_peer = active_fingerprint(
        lab, node_ip, 2380, "/etc/kubernetes/pki/etcd/peer.crt", "/etc/kubernetes/pki/etcd/peer.key"
    )
    active_comparison = {
        "etcd/server": active_server == after["etcd/server"]["sha256_fingerprint"],
        "etcd/peer": active_peer == after["etcd/peer"]["sha256_fingerprint"],
    }

    # The API write/read exercises the restarted apiserver's etcd client path. The
    # manifest reference check ties that running path to the renewed public client cert.
    manifest_refs_client = node(
        lab,
        "grep -F -- '--etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt' "
        "/etc/kubernetes/manifests/kube-apiserver.yaml >/dev/null",
    )
    previous = json.loads(lab.kubectl("get", "configmap", "cert-rotation-before", "-o", "json").stdout)
    retained = previous.get("data") == marker["data"]
    name = "cert-rotation-after"
    payload = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": name, "labels": {"app.kubernetes.io/managed-by": "saf-k8s-lab"}},
        "data": {"marker": "synthetic-post-rotation-readback-v1"},
    }
    lab.create(payload)
    readback = json.loads(lab.kubectl("get", "configmap", name, "-o", "json").stdout)
    data_ok = readback.get("data") == payload["data"]
    positive = (
        etcd_restarted and apiserver_restarted and all(active_comparison.values())
        and manifest_refs_client.returncode == 0 and data_ok and retained
    )
    lab.check(
        "positive",
        "Restarted etcd serves renewed server and peer certs, and the restarted apiserver stores and reads permitted data",
        positive,
        {"etcd_static_pod_restarted": etcd_restarted,
         "apiserver_static_pod_restarted": apiserver_restarted,
         "active_server_and_peer_match_renewed_receipts": active_comparison,
         "apiserver_manifest_references_renewed_client_cert_path": manifest_refs_client.returncode == 0,
         "permitted_api_write_readback": data_ok,
         "preexisting_data_retained": retained,
         "raw_evidence_file": RAW_FILE},
    )

    record_raw(lab, {
        "tested_versions": {"kubernetes": version, "kubeadm": node_version,
                            "node_image": NODE_IMAGE},
        "certificate_receipts_before": before,
        "certificate_receipts_after_partial_renewal": incomplete,
        "certificate_receipts_after": after,
        "disk_receipt_comparisons": per_class,
        "active_etcd_receipts": {"etcd/server": active_server, "etcd/peer": active_peer},
        "active_receipt_comparisons": active_comparison,
        "restart_and_api": {"etcd_static_pod_restarted": etcd_restarted,
                             "apiserver_static_pod_restarted": apiserver_restarted,
                             "apiserver_client_certificate_path_referenced": True,
                             "synthetic_configmap_data_readback": data_ok},
        "renewal_output": first.stdout.strip() + "\n" + renewal.stdout.strip(),
        "preexpiry_plan": {
            "lead_seconds": LEAD_SECONDS,
            "clock_basis": "synthetic_expiry_offsets_only",
            "all_due_role_order": list(planned_roles),
            "existing_first_phase_roles": initial_roles,
            "existing_followup_role": remaining_roles,
            "executed_renewal_command_count": len(initial_roles) + len(remaining_roles),
            "host_clock_changed": False,
            "role_boundary_predicates": planner_evidence["role_boundaries"],
        },
    })
