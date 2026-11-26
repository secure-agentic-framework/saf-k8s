"""Two-member native admission-policy drift, detection, and bounded repair test."""
import hashlib
import importlib.util
import json
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
NS = "saf-test"
MARKER = "saf-k8s.example/admission-drift-fixture"
MARKER_VALUE = "0910-027"
POLICY = "fixture-no-hostnetwork"
BINDING = "fixture-no-hostnetwork-binding"
REVISION_ANNOTATION = "saf-k8s.example/desired-revision"
DENIAL_REASON = "SAF-K8S-0910-027: hostNetwork=true is prohibited by the approved fixture policy"
DRIFT_WRITER = "fixture-drift-writer"
RECONCILER = "fixture-drift-reconciler"
CONSUMER = "fixture-independent-consumer"
MAX_RECONCILE_ATTEMPTS = 3
IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
SCOPE = (
    "One ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding on two owned Kind API servers. "
    "The policy denies Pod CREATE requests setting hostNetwork=true in one case-labeled namespace; "
    "ordinary hostNetwork=false Pods remain permitted. Remote drift changes only that binding's "
    "validationActions from Deny to Warn. A distinct scoped writer makes the change, a bounded "
    "reconciler restores the desired revision, and an independent consumer verifies actual API state. "
    "The additive scratch check reintroduces one drift and requires one actual CronJob-owned in-cluster "
    "pass plus an independent read of its metadata-only receipt. It does not prove recurring fleet monitoring "
    "or external alert delivery. All probe Pods use a nonexistent scheduler name and never run."
)


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest(value):
    return "sha256:" + hashlib.sha256(canon(value).encode()).hexdigest()


def row(kind, name, api, **fields):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields}


def identity(actor):
    return f"system:serviceaccount:{NS}:{actor}"


def call(kube, *args, actor=None, payload=None, allow_failure=False, timeout=25):
    actor_args = [f"--as={identity(actor)}"] if actor else []
    return kube(*actor_args, *args, payload=payload, allow_failure=allow_failure, timeout=timeout)


def create(kube, obj):
    call(kube, "create", "-f", "-", payload=json.dumps(obj))


def policy_objects(revision):
    selector = {"matchLabels": {MARKER: MARKER_VALUE}}
    policy = row("ValidatingAdmissionPolicy", POLICY, "admissionregistration.k8s.io/v1",
                 spec={
                     "failurePolicy": "Fail",
                     "matchConstraints": {
                         "matchPolicy": "Equivalent",
                         "namespaceSelector": selector,
                         "resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                            "operations": ["CREATE"], "resources": ["pods"],
                                            "scope": "Namespaced"}],
                     },
                     "validations": [{"expression": "!has(object.spec.hostNetwork) || object.spec.hostNetwork == false",
                                      "message": DENIAL_REASON, "reason": "Forbidden"}],
                 })
    binding = row("ValidatingAdmissionPolicyBinding", BINDING,
                  "admissionregistration.k8s.io/v1",
                  spec={"policyName": POLICY, "validationActions": ["Deny"],
                        "matchResources": {"namespaceSelector": selector}})
    binding["metadata"]["annotations"] = {REVISION_ANNOTATION: revision}
    return policy, binding


def revision_material(policy, binding):
    return {"policy_name": policy["metadata"]["name"], "policy_spec": policy["spec"],
            "binding_name": binding["metadata"]["name"], "binding_spec": binding["spec"]}


def probe(name, host_network):
    return row("Pod", name, "v1", metadata={
        "name": name, "namespace": NS, "labels": {MARKER: MARKER_VALUE}},
        spec={"restartPolicy": "Never", "schedulerName": "saf-fixture-no-scheduler",
              "automountServiceAccountToken": False,
              "schedulingGates": [{"name": "saf-k8s.example/fixture-never-run"}],
              "containers": [{"name": "inert", "image": IMAGE, "command": ["/bin/true"],
                              "securityContext": {"allowPrivilegeEscalation": False,
                                                  "capabilities": {"drop": ["ALL"]},
                                                  "runAsNonRoot": True, "runAsUser": 65534,
                                                  "seccompProfile": {"type": "RuntimeDefault"}}}],
              "hostNetwork": host_network})


def actual_policy_state(kube):
    policy = json.loads(call(kube, "get", "validatingadmissionpolicy", POLICY, "-o", "json").stdout)
    binding = json.loads(call(kube, "get", "validatingadmissionpolicybinding", BINDING, "-o", "json").stdout)
    projection = revision_material(
        {"metadata": {"name": policy["metadata"]["name"]}, "spec": policy["spec"]},
        {"metadata": {"name": binding["metadata"]["name"]}, "spec": binding["spec"]})
    return {"policy_present": True, "binding_present": True,
            "policy_and_binding_digest": digest(projection),
            "validation_actions": binding["spec"].get("validationActions"),
            "desired_revision_annotation": binding.get("metadata", {}).get("annotations", {}).get(REVISION_ANNOTATION)}


def defaulted_revision_material(kube, policy, binding):
    previews = [json.loads(call(kube, "create", "-f", "-", "--dry-run=server", "-o", "json",
                                payload=json.dumps(resource)).stdout)
                for resource in (policy, binding)]
    return revision_material(*previews)


def await_admission(lab, kube, name, allowed):
    deadline = time.monotonic() + 18
    while time.monotonic() < deadline:
        result = call(kube, "-n", NS, "create", "-f", "-", "--dry-run=server", "-o", "name",
                      actor=CONSUMER, payload=json.dumps(probe(name, True)), allow_failure=True)
        if allowed and result.returncode == 0:
            return
        if not allowed and result.returncode != 0 and DENIAL_REASON in result.stderr:
            return
        if result.returncode != 0 and DENIAL_REASON not in result.stderr:
            lab.block(f"The fixture dry-run request did not reach policy: {result.stderr.strip()}")
        time.sleep(0.25)
    lab.block(f"Native admission did not converge for {name}")


def normalized_admission(kube, name, host_network, actor=CONSUMER):
    obj = probe(name, host_network)
    result = call(kube, "-n", NS, "create", "-f", "-", "-o", "json",
                  actor=actor, payload=json.dumps(obj), allow_failure=True)
    if result.returncode == 0:
        persisted = json.loads(call(kube, "-n", NS, "get", "pod", name, "-o", "json",
                                    actor=actor).stdout)
        return {"decision": "allowed", "forbidden": False,
                "denial_reason": None, "resource_persisted": True,
                "resource_absent": False,
                "persisted_hostNetwork": persisted.get("spec", {}).get("hostNetwork", False),
                "scheduler_name": persisted.get("spec", {}).get("schedulerName")}
    persisted_check = call(kube, "-n", NS, "get", "pod", name, "-o", "name",
                           actor=actor, allow_failure=True)
    return {"decision": "denied" if "(Forbidden)" in result.stderr else "error",
            "forbidden": "(Forbidden)" in result.stderr,
            "denial_reason": DENIAL_REASON if DENIAL_REASON in result.stderr else None,
            "resource_persisted": False,
            "resource_absent": persisted_check.returncode != 0 and "(NotFound)" in persisted_check.stderr,
            "persisted_hostNetwork": None,
            "scheduler_name": None}


def create_rbac(kube):
    for actor in (DRIFT_WRITER, RECONCILER, CONSUMER):
        create(kube, row("ServiceAccount", actor, "v1", automountServiceAccountToken=False))
    for role, verbs in (("fixture-drift-writer", ["get", "patch"]),
                        ("fixture-drift-reconciler", ["get", "patch"]),
                        ("fixture-independent-consumer", ["get"])):
        create(kube, row("ClusterRole", role, "rbac.authorization.k8s.io/v1", rules=[{
            "apiGroups": ["admissionregistration.k8s.io"],
            "resources": ["validatingadmissionpolicybindings"],
            "resourceNames": [BINDING], "verbs": verbs,
        }]))
        actor = {"fixture-drift-writer": DRIFT_WRITER,
                 "fixture-drift-reconciler": RECONCILER,
                 "fixture-independent-consumer": CONSUMER}[role]
        create(kube, row("ClusterRoleBinding", role, "rbac.authorization.k8s.io/v1",
                         roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                                  "name": role},
                         subjects=[{"kind": "ServiceAccount", "name": actor, "namespace": NS}]))
    create(kube, row("Role", "fixture-pod-consumer", "rbac.authorization.k8s.io/v1", rules=[{
        "apiGroups": [""], "resources": ["pods"], "verbs": ["create", "get", "delete"],
    }]))
    create(kube, row("RoleBinding", "fixture-pod-consumer", "rbac.authorization.k8s.io/v1",
                     roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                              "name": "fixture-pod-consumer"},
                     subjects=[{"kind": "ServiceAccount", "name": CONSUMER, "namespace": NS}]))


def patch_binding(kube, actor, resource_version, actions, revision, timeout=25):
    patch = {"metadata": {"resourceVersion": resource_version,
                           "annotations": {REVISION_ANNOTATION: revision}},
             "spec": {"validationActions": actions}}
    return call(kube, "patch", "validatingadmissionpolicybinding", BINDING,
                "--type=merge", "-p", json.dumps(patch), actor=actor,
                allow_failure=True, timeout=timeout)


def bounded_reconcile(kube, revision):
    for attempt in range(1, MAX_RECONCILE_ATTEMPTS + 1):
        current = json.loads(call(kube, "get", "validatingadmissionpolicybinding", BINDING,
                                  "-o", "json", actor=RECONCILER, timeout=25).stdout)
        if current.get("spec", {}).get("validationActions") == ["Deny"] and current.get(
                "metadata", {}).get("annotations", {}).get(REVISION_ANNOTATION) == revision:
            return {"restored": True, "attempts": attempt - 1, "bounded": True}
        result = patch_binding(kube, RECONCILER, current["metadata"]["resourceVersion"],
                               ["Deny"], revision, timeout=25)
        if result.returncode == 0:
            verified = json.loads(call(kube, "get", "validatingadmissionpolicybinding", BINDING,
                                       "-o", "json", actor=RECONCILER, timeout=25).stdout)
            if verified.get("spec", {}).get("validationActions") == ["Deny"] and verified.get(
                    "metadata", {}).get("annotations", {}).get(REVISION_ANNOTATION) == revision:
                return {"restored": True, "attempts": attempt, "bounded": True}
        elif "Conflict" not in result.stderr:
            return {"restored": False, "attempts": attempt, "bounded": True,
                    "forbidden": "Forbidden" in result.stderr}
    return {"restored": False, "attempts": MAX_RECONCILE_ATTEMPTS, "bounded": True}


def verify_denial(row_result):
    return (row_result["decision"] == "denied" and row_result["forbidden"]
            and row_result["denial_reason"] == DENIAL_REASON
            and row_result["resource_persisted"] is False and row_result["resource_absent"] is True)



SCHEDULED_RECONCILER = "fixture-scheduled-reconciler"
ALERT_CONSUMER = "fixture-alert-consumer"
SCHEDULED_CRONJOB = "fixture-drift-scheduled-reconcile"
ALERT_CONFIG = "fixture-scheduled-reconcile-code"
ALERT_LABEL = "app.kubernetes.io/name=fixture-drift-scheduled-reconcile"


def run_scheduled_alert(lab, peer, revision, peer_uid, runtime_image):
    """Exercise one actual CronJob-owned, in-cluster drift detection and repair."""
    directory = HERE
    worker = (directory / "drift_monitor.py").read_text()
    create(peer, row("ConfigMap", ALERT_CONFIG, "v1", immutable=True,
                     data={"drift_monitor.py": worker}))
    # The runner command supports no shell interpolation here: placeholders are
    # replaced in a local manifest string and passed as kubectl stdin.
    manifest = (directory / "cronjob.yaml").read_text()
    manifest = manifest.replace("REPLACE_EXPECTED_REVISION", revision)
    manifest = manifest.replace("REPLACE_MEMBER_UID", peer_uid)
    manifest = manifest.replace(
        "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90",
        runtime_image)
    manifest = manifest.replace("fixture-drift-scheduled-code", ALERT_CONFIG)
    applied = peer("apply", "-f", "-", payload=manifest, allow_failure=True, timeout=35)
    if applied.returncode != 0:
        lab.block("Could not install the namespace-scoped scheduled monitor")

    # Reintroduce the known harmless one-field drift so the scheduled workload,
    # rather than the earlier host process, must observe and repair this instance.
    current = json.loads(call(peer, "get", "validatingadmissionpolicybinding", BINDING,
                              "-o", "json", actor=DRIFT_WRITER).stdout)
    drift = patch_binding(peer, DRIFT_WRITER, current["metadata"]["resourceVersion"],
                          ["Warn"], revision)
    if drift.returncode != 0:
        lab.block("Could not inject the exact owned scheduled-pass drift")
    injected = actual_policy_state(peer)
    if injected["validation_actions"] != ["Warn"] or injected["desired_revision_annotation"] != revision:
        lab.block("Scheduled-pass drift did not match the intended one-field change")

    call(peer, "patch", "cronjob", SCHEDULED_CRONJOB, "--type=merge",
         "-p", '{"spec":{"suspend":false}}')
    cronjob = json.loads(call(peer, "get", "cronjob", SCHEDULED_CRONJOB, "-o", "json").stdout)
    cron_uid = cronjob["metadata"]["uid"]
    spec = cronjob.get("spec", {})
    pod_spec = spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
    container = pod_spec.get("containers", [{}])[0]
    role = json.loads(call(peer, "get", "clusterrole", SCHEDULED_RECONCILER, "-o", "json").stdout)
    rules = role.get("rules", [])
    exact_rule = (len(rules) == 1
                  and rules[0].get("apiGroups") == ["admissionregistration.k8s.io"]
                  and rules[0].get("resources") == ["validatingadmissionpolicybindings"]
                  and rules[0].get("resourceNames") == [BINDING]
                  and sorted(rules[0].get("verbs", [])) == ["get", "patch"])

    jobs = []
    alert_data = None
    alert_immutable = False
    owned_job = None
    deadline = time.monotonic() + 105
    while time.monotonic() < deadline:
        listing = json.loads(call(peer, "get", "jobs", "-l", ALERT_LABEL, "-o", "json").stdout)
        jobs = listing.get("items", [])
        owned = [job for job in jobs
                 if job["metadata"].get("annotations", {}).get("batch.kubernetes.io/cronjob-scheduled-timestamp")
                 and any(ref.get("kind") == "CronJob" and ref.get("uid") == cron_uid
                         and ref.get("controller") is True
                         for ref in job.get("metadata", {}).get("ownerReferences", []))]
        for failed_job in owned:
            if failed_job.get("status", {}).get("failed", 0) > 0:
                failed_name = failed_job["metadata"]["name"]
                call(peer, "logs", f"job/{failed_name}", allow_failure=True, timeout=15)
                lab.block("The exact CronJob-owned drift monitor failed")
        owned = [job for job in owned if job.get("status", {}).get("succeeded") == 1]
        if owned:
            owned_job = sorted(owned, key=lambda item: item["metadata"]["name"])[-1]
            alert_name = "fixture-drift-alert-" + owned_job["metadata"]["name"][-35:]
            observed = call(peer, "get", "configmap", alert_name, "-o", "json",
                            actor=ALERT_CONSUMER, allow_failure=True)
            if observed.returncode == 0:
                alert_record = json.loads(observed.stdout)
                alert_data = alert_record.get("data", {})
                alert_immutable = alert_record.get("immutable") is True
                break
        time.sleep(2)
    call(peer, "patch", "cronjob", SCHEDULED_CRONJOB, "--type=merge",
         "-p", '{"spec":{"suspend":true}}', allow_failure=True, timeout=15)

    after = actual_policy_state(peer)
    worker_job_name = owned_job.get("metadata", {}).get("name") if owned_job else None
    if not alert_data and worker_job_name:
        name = "fixture-drift-alert-" + worker_job_name[-35:]
        observed = call(peer, "get", "configmap", name, "-o", "json",
                        actor=ALERT_CONSUMER, allow_failure=True)
        if observed.returncode == 0:
            alert_record = json.loads(observed.stdout)
            alert_data = alert_record.get("data", {})
            alert_immutable = alert_record.get("immutable") is True
    alert_timestamp = None
    if alert_data:
        try:
            alert_timestamp = time.strptime(alert_data.get("detected_at_utc", ""), "%Y-%m-%dT%H:%M:%S%z")
        except ValueError:
            pass
    subject = f"system:serviceaccount:{NS}:{SCHEDULED_RECONCILER}"
    groups = ("--as-group=system:serviceaccounts", f"--as-group=system:serviceaccounts:{NS}",
              "--as-group=system:authenticated")
    permissions = [
        ("get", f"validatingadmissionpolicybindings/{BINDING}", "yes"),
        ("patch", f"validatingadmissionpolicybindings/{BINDING}", "yes"),
        ("get", "secrets", "no"), ("create", "pods", "no"), ("patch", "validatingadmissionpolicies", "no"),
    ]
    rbac_ok = all(call(peer, "auth", "can-i", verb, resource, "--as", subject, *groups,
                       allow_failure=True, timeout=15).stdout.strip() == expected
                  for verb, resource, expected in permissions)
    alert_ok = bool(alert_data) and alert_immutable and (
        alert_data.get("event") == "admission-policy-binding-drift-repaired"
        and alert_data.get("member_uid") == peer_uid
        and alert_data.get("binding") == BINDING
        and alert_data.get("desired_revision") == revision
        and alert_data.get("observed_revision") == revision
        and alert_data.get("observed_actions") == '["Warn"]'
        and alert_data.get("repaired_revision") == revision
        and alert_data.get("repaired_actions") == '["Deny"]'
        and alert_data.get("repair_verified") == "true"
        and alert_timestamp is not None)
    secure_pod = (pod_spec.get("serviceAccountName") == SCHEDULED_RECONCILER
                  and pod_spec.get("automountServiceAccountToken") is True
                  and pod_spec.get("securityContext", {}).get("runAsNonRoot") is True
                  and container.get("image") == runtime_image
                  and container.get("securityContext", {}).get("readOnlyRootFilesystem") is True
                  and container.get("securityContext", {}).get("allowPrivilegeEscalation") is False
                  and container.get("securityContext", {}).get("capabilities", {}).get("drop") == ["ALL"]
                  and not any("hostPath" in volume for volume in pod_spec.get("volumes", [])))
    schedule_ok = (spec.get("schedule") == "* * * * *"
                   and spec.get("concurrencyPolicy") == "Forbid"
                   and spec.get("startingDeadlineSeconds") == 50
                   and spec.get("jobTemplate", {}).get("spec", {}).get("backoffLimit") == 0)
    receipt_read_ok = alert_data is not None
    matched = (exact_rule and schedule_ok and secure_pod and rbac_ok and receipt_read_ok and alert_ok
               and owned_job is not None
               and injected["validation_actions"] == ["Warn"]
               and after["validation_actions"] == ["Deny"]
               and after["policy_and_binding_digest"] == revision
               and after["desired_revision_annotation"] == revision)
    lab.check("scheduled_alert",
              "A CronJob-owned workload detects one binding drift, repairs it, and emits an independently read receipt",
              matched, {"cronjob_owned_successful_job": owned_job is not None,
                        "scheduled_spec_ok": schedule_ok,
                        "exact_binding_rbac": exact_rule, "authorization_decisions": rbac_ok,
                        "workload_security_shape": secure_pod, "independent_receipt_read": receipt_read_ok,
                        "receipt_matches_observed_and_repaired_state": alert_ok,
                        "binding_restored": after["validation_actions"] == ["Deny"]
                        and after["desired_revision_annotation"] == revision})
    (lab.evidence / "scheduled-drift-alert.json").write_text(json.dumps(
        {"scheduled_job_owned_by_cronjob": owned_job is not None,
         "alert_receipt": alert_data, "binding_after_job": after,
         "checks": {"schedule": schedule_ok, "rbac": rbac_ok, "secure_workload": secure_pod,
                    "independent_read": receipt_read_ok, "receipt_matches": alert_ok}},
        sort_keys=True, indent=2) + "\n")


def run(lab):
    # The helper creates a second owned Kind API server on the private test bridge.
    helper_spec = importlib.util.spec_from_file_location(
        "saf_0910_020_owned_peer", HERE.parent / "SAF-K8S-0910-020" / "owned_peer.py")
    if helper_spec is None or helper_spec.loader is None:
        lab.block("The adjacent SAF-K8S-0910-020 owned-peer helper is unavailable")
    helper = importlib.util.module_from_spec(helper_spec)
    helper_spec.loader.exec_module(helper)

    runtime_spec = importlib.util.spec_from_file_location(
        "saf_drift_runtime", HERE.parent / "SAF-K8S-0908-001" / "case.py")
    runtime = importlib.util.module_from_spec(runtime_spec)
    runtime_spec.loader.exec_module(runtime)
    runtime_image = runtime.load_runtime(lab)
    with helper.owned_peer(lab, runtime_image) as (peer, _):
        local_uid = lab.kubectl("get", "namespace", "kube-system", "-o",
                                "jsonpath={.metadata.uid}").stdout.strip()
        peer_uid = peer("get", "namespace", "kube-system", "-o",
                        "jsonpath={.metadata.uid}").stdout.strip()
        if not local_uid or not peer_uid or local_uid == peer_uid:
            lab.block("The two admission observations must come from distinct API servers")

        local = lambda *args, **kwargs: lab.kubectl("-n", NS, *args, **kwargs)
        members = {"healthy": local, "remote": peer}
        source_namespace = call(local, "get", "namespace", NS, "-o", "json", allow_failure=True)
        if source_namespace.returncode != 0:
            if "(NotFound)" not in source_namespace.stderr:
                lab.block("Could not verify the source fixture namespace")
            create(local, row("Namespace", NS, "v1", metadata={"name": NS,
                         "labels": {MARKER: MARKER_VALUE}}))
        peer_namespace = call(peer, "get", "namespace", NS, "-o", "json", allow_failure=True)
        if peer_namespace.returncode != 0:
            lab.block("The owned peer fixture namespace is unavailable")
        for kube in members.values():
            call(kube, "label", "namespace", NS, f"{MARKER}={MARKER_VALUE}", "--overwrite")
            create_rbac(kube)

        # Hash only the declared policy and binding state; the binding records this
        # immutable desired revision for independent observation.
        policy, binding = policy_objects("pending")
        previews = [defaulted_revision_material(kube, policy, binding) for kube in members.values()]
        if previews[0] != previews[1]:
            lab.block("The member API servers use different defaults for the approved policy bundle")
        revision = expected_digest = digest(previews[0])
        policy, binding = policy_objects(revision)
        for kube in members.values():
            create(kube, policy)
            create(kube, binding)

        # Wait for the native admission decision on each API server, then compare
        # policy and binding projections before testing any drift behavior.
        initial_denials = {}
        for member, kube in members.items():
            name = f"initial-denied-{member}"
            await_admission(lab, kube, name, allowed=False)
            initial_denials[member] = normalized_admission(kube, name, True)
        initial_allowed = {member: normalized_admission(kube, f"initial-allowed-{member}", False)
                           for member, kube in members.items()}
        initial_states = {member: actual_policy_state(kube) for member, kube in members.items()}
        initial_ok = all(state["policy_and_binding_digest"] == expected_digest
                         and state["validation_actions"] == ["Deny"]
                         and state["desired_revision_annotation"] == revision
                         for state in initial_states.values())
        initial_ok = initial_ok and all(verify_denial(value) for value in initial_denials.values())
        initial_ok = initial_ok and all(value["decision"] == "allowed"
                                        and value["resource_persisted"]
                                        and value["persisted_hostNetwork"] is False
                                        for value in initial_allowed.values())
        lab.check("baseline", "Both API servers start at the same native admission revision",
                  initial_ok, {"desired_revision": revision, "desired_digest": expected_digest,
                               "actual": initial_states, "denied": initial_denials,
                               "permitted": initial_allowed})

        remote_before = json.loads(call(peer, "get", "validatingadmissionpolicybinding", BINDING,
                                        "-o", "json", actor=DRIFT_WRITER).stdout)
        drift_write = patch_binding(peer, DRIFT_WRITER, remote_before["metadata"]["resourceVersion"],
                                    ["Warn"], revision)
        if drift_write.returncode:
            lab.block("Scoped drift writer could not change only the owned remote policy binding")
        desired_remote = {"revision": revision, "validationActions": ["Deny"]}
        actual_remote_before = actual_policy_state(peer)
        source_during_drift = actual_policy_state(lab.kubectl)
        divergence = {"desired": desired_remote,
                      "actual": {"revision_annotation": actual_remote_before["desired_revision_annotation"],
                                 "validationActions": actual_remote_before["validation_actions"],
                                 "policy_and_binding_digest": actual_remote_before["policy_and_binding_digest"],
                                 "desired_digest": expected_digest},
                      "healthy_member": source_during_drift}
        await_admission(lab, peer, "drift-allowed-hostnetwork", allowed=True)
        untreated_remote = normalized_admission(peer, "drift-allowed-hostnetwork", True)
        healthy_denial_during_drift = normalized_admission(lab.kubectl, "healthy-denied-during-drift", True)
        # Prove the writer's authority ends at this one binding.
        writer_scope_probe = call(peer, "patch", "validatingadmissionpolicy", POLICY,
                                  "--type=merge", "-p", json.dumps({"spec": {"failurePolicy": "Ignore"}}),
                                  actor=DRIFT_WRITER, allow_failure=True)
        drift_ok = (drift_write.returncode == 0
                    and actual_remote_before["validation_actions"] == ["Warn"]
                    and actual_remote_before["policy_and_binding_digest"] != expected_digest
                    and source_during_drift["policy_and_binding_digest"] == expected_digest
                    and verify_denial(healthy_denial_during_drift)
                    and untreated_remote["decision"] == "allowed"
                    and untreated_remote["resource_persisted"]
                    and untreated_remote["persisted_hostNetwork"] is True
                    and untreated_remote["scheduler_name"] == "saf-fixture-no-scheduler"
                    and writer_scope_probe.returncode != 0
                    and "Forbidden" in writer_scope_probe.stderr)
        lab.check("red", "Scoped remote binding drift is visible while the healthy member still denies",
                  drift_ok, {"desired_vs_actual": divergence,
                             "untreated_remote_decision": untreated_remote,
                             "healthy_member_decision": healthy_denial_during_drift,
                             "writer_out_of_scope_denied": writer_scope_probe.returncode != 0
                             and "Forbidden" in writer_scope_probe.stderr})

        reconcile = bounded_reconcile(peer, revision)
        repaired_remote = actual_policy_state(peer)
        repaired_healthy = actual_policy_state(lab.kubectl)
        # This consumer identity has read-only access to the binding and namespaced
        # probe Pods. It performs fresh CREATE requests after the repair.
        post_denials = {}
        for member, kube in members.items():
            name = f"post-repair-denied-{member}"
            await_admission(lab, kube, name, allowed=False)
            post_denials[member] = normalized_admission(kube, name, True)
        consumer_binding = json.loads(call(peer, "get", "validatingadmissionpolicybinding", BINDING,
                                           "-o", "json", actor=CONSUMER).stdout)
        post_allowed = {member: normalized_admission(kube, f"post-repair-allowed-{member}", False)
                        for member, kube in members.items()}
        old_drift_pod = json.loads(call(peer, "get", "pod", "drift-allowed-hostnetwork", "-o", "json",
                                        actor=CONSUMER).stdout)
        call(peer, "delete", "pod", "drift-allowed-hostnetwork", actor=CONSUMER)
        cleanup_deadline = time.monotonic() + 10
        old_pod_absent = call(peer, "get", "pod", "drift-allowed-hostnetwork", "-o", "name",
                              actor=CONSUMER, allow_failure=True)
        while (old_pod_absent.returncode == 0 and time.monotonic() < cleanup_deadline):
            time.sleep(0.25)
            old_pod_absent = call(peer, "get", "pod", "drift-allowed-hostnetwork", "-o", "name",
                                  actor=CONSUMER, allow_failure=True)
        consumer_patch_probe = call(peer, "patch", "validatingadmissionpolicybinding", BINDING,
                                    "--type=merge", "-p", json.dumps({"spec": {"validationActions": ["Warn"]}}),
                                    actor=CONSUMER, allow_failure=True)
        post_ok = (reconcile["restored"] and reconcile["bounded"]
                   and reconcile["attempts"] <= MAX_RECONCILE_ATTEMPTS
                   and repaired_remote["policy_and_binding_digest"] == expected_digest
                   and repaired_remote["validation_actions"] == ["Deny"]
                   and repaired_remote["desired_revision_annotation"] == revision
                   and repaired_healthy["policy_and_binding_digest"] == expected_digest
                   and repaired_healthy["validation_actions"] == ["Deny"]
                   and repaired_healthy["desired_revision_annotation"] == revision
                   and consumer_binding.get("spec", {}).get("validationActions") == ["Deny"]
                   and consumer_binding.get("metadata", {}).get("annotations", {}).get(
                       REVISION_ANNOTATION) == revision
                   and all(verify_denial(value) for value in post_denials.values())
                   and all(value["decision"] == "allowed" and value["resource_persisted"]
                           and value["persisted_hostNetwork"] is False for value in post_allowed.values())
                   and old_drift_pod.get("spec", {}).get("hostNetwork") is True
                   and old_pod_absent.returncode != 0 and "(NotFound)" in old_pod_absent.stderr
                   and consumer_patch_probe.returncode != 0
                   and "Forbidden" in consumer_patch_probe.stderr)
        lab.check("green", "Bounded repair restores both members and independent consumer confirms corrected API behavior",
                  post_ok, {"reconciliation": reconcile,
                            "after_repair": {"healthy": repaired_healthy, "remote": repaired_remote},
                            "independent_consumer_observed": {
                                "validation_actions": consumer_binding.get("spec", {}).get("validationActions"),
                                "desired_revision": consumer_binding.get("metadata", {}).get("annotations", {}).get(
                                    REVISION_ANNOTATION)},
                            "fresh_denials": post_denials, "permitted_paths": post_allowed,
                            "previously_admitted_drift_resource": {
                                "present_before_cleanup": True,
                                "hostNetwork": old_drift_pod.get("spec", {}).get("hostNetwork") is True,
                                "absent_after_cleanup": old_pod_absent.returncode != 0
                                and "(NotFound)" in old_pod_absent.stderr},
                            "consumer_binding_patch_denied": consumer_patch_probe.returncode != 0
                            and "Forbidden" in consumer_patch_probe.stderr})

        lab.check("positive", "Both members continue to admit and persist the compliant case-owned Pod",
                  all(row["decision"] == "allowed" and row["resource_persisted"]
                      and row["persisted_hostNetwork"] is False for row in post_allowed.values()), post_allowed)
        run_scheduled_alert(lab, peer, revision, peer_uid, runtime_image)
        evidence = {"case": "SAF-K8S-0910-027", "scope": SCOPE,
                    "policy_mechanism": "ValidatingAdmissionPolicy",
                    "desired_revision": revision, "desired_policy_and_binding_digest": expected_digest,
                    "members": {"healthy": {"cluster_identity": "local-owned-api"},
                                "remote": {"cluster_identity": "owned-peer-api"}},
                    "baseline": {"actual": initial_states, "denied": initial_denials,
                                 "permitted": initial_allowed},
                    "drift": {"desired_vs_actual": divergence,
                              "remote_untreated_decision": untreated_remote,
                              "healthy_member_denial": healthy_denial_during_drift},
                    "repair": {"result": reconcile, "actual": {"healthy": repaired_healthy,
                              "remote": repaired_remote}, "fresh_denials": post_denials,
                              "permitted": post_allowed,
                              "drift_resource_cleanup_verified": old_pod_absent.returncode != 0
                              and "(NotFound)" in old_pod_absent.stderr}}
        (lab.evidence / "admission-drift-observations.json").write_text(
            json.dumps(evidence, sort_keys=True, indent=2) + "\n")
