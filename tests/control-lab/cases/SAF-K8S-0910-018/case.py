"""Synthetic posture-aware placement gate for SAF-K8S-0910-018."""
import hashlib
import importlib.util
import json
import time
from pathlib import Path

from fixtures import BUSYBOX_IMAGE

HERE = Path(__file__).resolve().parent
NS_CONTROL = "saf018-control"
NS_WORK = "saf018-workloads"
OBSERVER = "saf018-observer"
APPROVER = "saf018-reviewer"
PLACER = "saf018-placer"
POLICY = "saf018-fixture-baseline-v1"
MAX_AGE_SECONDS = 120
MAX_CLAIM_BYTES = 4096
EVIDENCE = "saf018-posture-evidence"
APPROVAL = "saf018-posture-approval"
BASELINE = "saf018-unchecked-baseline"
CANDIDATE = "saf018-reviewed-candidate"
REEVALUATION_CANDIDATE = "saf018-policy-drift-candidate"
DENIAL = "SAF-K8S-0910-018: unsafe synthetic workload rejected"
SCOPE = (
    "Two separately owned Kind API servers; one harmless BusyBox Deployment; server-side "
    "admission evidence bound to member UID, endpoint, policy identity and exact candidate "
    "revision; separate observation, reviewer approval and placement identities."
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("The reviewed adjacent owned-peer helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Target:
    def __init__(self, name, kube):
        self.name = name
        self.kube = kube

    def call(self, *args, **kwargs):
        result = self.kube(*args, **kwargs)
        if result.returncode:
            raise RuntimeError(f"{self.name}: kubectl {' '.join(args)} failed")
        return result.stdout

    def json(self, *args):
        return json.loads(self.call(*args))


def row(kind, name, api="v1", **fields):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def actor(name):
    return f"system:serviceaccount:{NS_CONTROL}:{name}"


def kube_system_uid(target):
    return target.call("get", "namespace", "kube-system", "-o",
                       "jsonpath={.metadata.uid}").strip()


def endpoint(target):
    config = target.json("config", "view", "--minify", "-o", "json")
    return config["clusters"][0]["cluster"]["server"]


def candidate(name):
    labels = {"app": name, "saf-fixture": "posture-placement"}
    return row("Deployment", name, "apps/v1", metadata={
        "name": name,
        "labels": {"saf-fixture": "posture-placement"},
        "annotations": {},
    }, spec={
        "replicas": 1,
        "selector": {"matchLabels": labels},
        "template": {"metadata": {"labels": labels}, "spec": {
            "automountServiceAccountToken": False,
            "terminationGracePeriodSeconds": 3,
            "containers": [{
                "name": "fixture", "image": BUSYBOX_IMAGE,
                "command": ["sleep", "3600"],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "privileged": False,
                    "runAsNonRoot": True,
                    "runAsUser": 65534,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
            }],
        }},
    })


def unsafe_probe(obj):
    probe = json.loads(json.dumps(obj))
    probe["metadata"]["name"] = probe["metadata"]["name"] + "-unsafe-probe"
    probe["spec"]["template"]["spec"]["containers"][0]["securityContext"]["seccompProfile"] = {"type": "Unconfined"}
    return probe


def create(target, obj, namespace=None, as_actor=None):
    args = ["create"]
    if namespace:
        args += ["-n", namespace]
    args += ["-f", "-", "-o", "json"]
    if as_actor:
        args += ["--as", as_actor]
    raw = target.call(*args, payload=json.dumps(obj, sort_keys=True))
    return json.loads(raw)


def install_posture_control(target):
    policy = row("ValidatingAdmissionPolicy", POLICY,
                 "admissionregistration.k8s.io/v1", spec={
        "failurePolicy": "Fail",
        "matchConstraints": {"resourceRules": [{
            "apiGroups": ["apps"], "apiVersions": ["v1"],
            "operations": ["CREATE"], "resources": ["deployments"],
        }]},
        "validations": [{
            "expression": (
                "object.spec.template.spec.containers.all(c, has(c.securityContext) && "
                "c.securityContext.allowPrivilegeEscalation == false && "
                "c.securityContext.privileged != true && "
                "has(c.securityContext.seccompProfile) && "
                "c.securityContext.seccompProfile.type == 'RuntimeDefault')"
            ),
            "message": DENIAL, "reason": "Forbidden",
        }],
    })
    binding = row("ValidatingAdmissionPolicyBinding", POLICY,
                  "admissionregistration.k8s.io/v1", spec={
        "policyName": POLICY,
        "validationActions": ["Deny" if target.name == "hub" else "Warn"],
        "matchResources": {"namespaceSelector": {"matchLabels": {
            "saf-fixture": "posture-placement",
        }}},
    })
    target.call("create", "-f", "-", payload=json.dumps(policy, sort_keys=True))
    target.call("create", "-f", "-", payload=json.dumps(binding, sort_keys=True))
    deadline = time.monotonic() + 25
    installed = None
    while time.monotonic() < deadline:
        obj = target.json("get", "validatingadmissionpolicy", POLICY, "-o", "json")
        checking = obj.get("status", {}).get("typeChecking")
        if isinstance(checking, dict) and not checking.get("expressionWarnings", []):
            installed = obj
            break
        time.sleep(0.25)
    if installed is None:
        raise RuntimeError("Native posture policy did not type-check cleanly")
    binding_raw = target.call("get", "validatingadmissionpolicybinding", POLICY, "-o", "json")
    installed_binding = json.loads(binding_raw)
    uid = installed.get("metadata", {}).get("uid")
    binding_uid = installed_binding.get("metadata", {}).get("uid")
    if (not uid or not binding_uid
            or installed.get("spec", {}).get("failurePolicy") != "Fail"
            or installed_binding.get("spec", {}).get("policyName") != POLICY):
        raise RuntimeError(f"{target.name}: posture policy is not observed as active")
    return {"name": POLICY, "uid": uid,
            "spec_sha256": digest(installed.get("spec", {})),
            "binding_uid": binding_uid,
            "binding_spec_sha256": digest(installed_binding.get("spec", {})),
            "failure_policy": "Fail"}


def admission_result(target, obj):
    result = target.kube("-n", NS_WORK, "create", "-f", "-",
                         "--dry-run=server", "-o", "name", "--as", actor(PLACER),
                         payload=json.dumps(obj, sort_keys=True), allow_failure=True)
    if result.returncode == 0:
        return {"decision": "accepted", "signal": "server-dry-run-created"}
    if "Forbidden" in result.stderr and DENIAL in result.stderr:
        return {"decision": "denied-by-policy", "signal": DENIAL}
    return {"decision": "unexpected-error", "signal": "unclassified-api-denial"}


def ready_nodes(target):
    nodes = target.json("get", "nodes", "-o", "json")["items"]
    return bool(nodes) and all(
        any(c["type"] == "Ready" and c["status"] == "True" for c in node["status"]["conditions"])
        for node in nodes)


def await_posture(lab, target, unsafe, expected):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        result = admission_result(target, unsafe)
        if result["decision"] == expected:
            return result
        if result["decision"] == "unexpected-error":
            break
        time.sleep(0.25)
    lab.block(f"Native posture probe did not converge for {target.name}: {result}")


def claim(target, name):
    raw = target.kube("-n", NS_CONTROL, "get", "configmap", name,
                      "-o", "json", allow_failure=True)
    if raw.returncode:
        return None
    try:
        value = json.loads(raw.stdout).get("data", {}).get("claim.json")
    except (TypeError, ValueError):
        return None
    if not isinstance(value, str) or len(value.encode()) > MAX_CLAIM_BYTES:
        return None
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return None


def write_claim(target, name, value, who):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode()) > MAX_CLAIM_BYTES:
        raise RuntimeError("posture claim exceeds the bounded receipt size")
    identity = actor(who)
    target.call("patch", "-n", NS_CONTROL, "configmap", name,
                "--type=merge", "-p", json.dumps({"data": {"claim.json": encoded}}),
                "--as", identity)


def approval_record(candidate_hash, member_uid):
    return {"decision": "approved", "candidate_sha256": candidate_hash,
            "member_uid": member_uid, "reviewer": APPROVER,
            "approval_ref": "fixture-review-018-001"}


def check_eligibility(target, candidate_hash, member_uid, policy_id, now=None, *, candidate_name=CANDIDATE):
    now = int(time.time()) if now is None else int(now)
    if not ready_nodes(target):
        return False, "member-not-ready"
    evidence = claim(target, EVIDENCE)
    if not evidence:
        return False, "missing-evidence"
    try:
        live_policy = target.json("get", "validatingadmissionpolicy", POLICY, "-o", "json")
        live_binding = target.json("get", "validatingadmissionpolicybinding", POLICY, "-o", "json")
    except (RuntimeError, ValueError, KeyError):
        return False, "live-policy-state-unavailable"
    live_policy_id = {
        "name": POLICY,
        "uid": live_policy.get("metadata", {}).get("uid"),
        "spec_sha256": digest(live_policy.get("spec", {})),
        "binding_uid": live_binding.get("metadata", {}).get("uid"),
        "binding_spec_sha256": digest(live_binding.get("spec", {})),
        "failure_policy": live_policy.get("spec", {}).get("failurePolicy"),
    }
    if live_policy_id != policy_id or live_binding.get("spec", {}).get("policyName") != POLICY:
        return False, "live-policy-identity-mismatch"
    required = {
        "member_uid": member_uid,
        "api_endpoint": endpoint(target),
        "candidate_sha256": candidate_hash,
        "candidate_namespace": NS_WORK,
        "candidate_name": candidate_name,
        "policy": policy_id, "nodes_ready": True,
        "safe_admission": {"decision": "accepted", "signal": "server-dry-run-created"},
        "unsafe_probe": {"decision": "denied-by-policy", "signal": DENIAL},
    }
    if any(evidence.get(key) != value for key, value in required.items()):
        return False, "evidence-binding-or-enforcement-mismatch"
    observed_at = evidence.get("observed_at_epoch")
    if not isinstance(observed_at, int) or observed_at > now or now - observed_at > MAX_AGE_SECONDS:
        return False, "stale-evidence"
    if evidence.get("receipt_sha256") != digest({k: v for k, v in evidence.items()
                                                 if k != "receipt_sha256"}):
        return False, "receipt-integrity-mismatch"
    approved = claim(target, APPROVAL)
    expected_approval = approval_record(candidate_hash, member_uid)
    expected_approval["evidence_sha256"] = evidence["receipt_sha256"]
    if not approved or any(approved.get(k) != v for k, v in expected_approval.items()):
        return False, "approval-missing-or-mismatched"
    return True, "eligible"


def place_if_eligible(target, workload, candidate_hash, member_uid, policy_id):
    if digest(workload) != candidate_hash:
        return {"decision": "blocked", "reason": "workload-digest-mismatch", "created": False}
    ok, reason = check_eligibility(target, candidate_hash, member_uid, policy_id,
                                   candidate_name=workload["metadata"]["name"])
    if not ok:
        return {"decision": "blocked", "reason": reason, "created": False}
    try:
        create(target, workload, NS_WORK, actor(PLACER))
    except RuntimeError:
        return {"decision": "unexpected-api-error", "reason": "create-failed", "created": False}
    return {"decision": "placed", "reason": "fresh-approved-posture", "created": True}


def object_exists(target, name):
    result = target.kube("-n", NS_WORK, "get", "deployment", name,
                         "-o", "name", allow_failure=True)
    return result.returncode == 0


def set_trial_claim(target, value):
    if value is None:
        target.call("delete", "-n", NS_CONTROL, "configmap", EVIDENCE,
                    "--ignore-not-found=true")
    else:
        if claim(target, EVIDENCE) is None:
            create(target, row("ConfigMap", EVIDENCE, data={"claim.json": "{}"}), NS_CONTROL)
        write_claim(target, EVIDENCE, value, OBSERVER)


def forbidden_patch(target, identity, name):
    result = target.kube("patch", "-n", NS_CONTROL, "configmap", name,
                         "--type=merge", "-p", '{"data":{"unauthorized":"1"}}',
                         "--as", identity, allow_failure=True)
    return result.returncode != 0 and "Forbidden" in result.stderr


def setup(target):
    target.call("create", "namespace", NS_CONTROL)
    target.call("create", "namespace", NS_WORK)
    target.call("label", "namespace", NS_WORK, "saf-fixture=posture-placement")
    for name in (OBSERVER, APPROVER, PLACER):
        create(target, row("ServiceAccount", name, automountServiceAccountToken=False), NS_CONTROL)
    for sa, rules in (
        (OBSERVER, [{"apiGroups": [""], "resources": ["configmaps"],
                    "resourceNames": [EVIDENCE], "verbs": ["get", "patch"]}]),
        (APPROVER, [{"apiGroups": [""], "resources": ["configmaps"],
                     "resourceNames": [APPROVAL], "verbs": ["get", "patch"]}]),
    ):
        role = row("Role", sa, "rbac.authorization.k8s.io/v1", rules=rules)
        create(target, role, NS_CONTROL)
        binding = row("RoleBinding", sa, "rbac.authorization.k8s.io/v1",
                      roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": sa},
                      subjects=[{"kind": "ServiceAccount", "name": sa, "namespace": NS_CONTROL}])
        create(target, binding, NS_CONTROL)
    create(target, row("ConfigMap", EVIDENCE, data={"claim.json": "{}"}), NS_CONTROL)
    role = row("Role", PLACER, "rbac.authorization.k8s.io/v1", rules=[{
        "apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["create", "get"]
    }])
    create(target, role, NS_WORK)
    binding = row("RoleBinding", PLACER, "rbac.authorization.k8s.io/v1",
                  roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": PLACER},
                  subjects=[{"kind": "ServiceAccount", "name": PLACER, "namespace": NS_CONTROL}])
    create(target, binding, NS_WORK)
    create(target, row("ConfigMap", APPROVAL, data={"claim.json": "{}"}), NS_CONTROL)


def run(lab):
    peer = load(HERE.parent / "SAF-K8S-0910-020" / "owned_peer.py", "saf018_owned_peer")
    runtime = load(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf018_pinned_runtime")
    with peer.owned_peer(lab, runtime.load_runtime(lab)) as (peer_kube, _):
        targets = (Target("hub", lab.kubectl), Target("peer", peer_kube))
        identities = {}
        for target in targets:
            identities[target.name] = {"uid": kube_system_uid(target), "endpoint": endpoint(target)}
        if (not all(v["uid"] and v["endpoint"] for v in identities.values())
                or identities["hub"]["uid"] == identities["peer"]["uid"]):
            lab.block("The two owned API servers must have distinct observed Kubernetes identities")

        # Deliberately demonstrate placement while the condition is unchecked.
        for target in targets:
            setup(target)
        baseline_obj = candidate(BASELINE)
        baseline_results = {}
        for target in targets:
            try:
                create(target, baseline_obj, NS_WORK, actor(PLACER))
                baseline_results[target.name] = "created"
            except RuntimeError:
                baseline_results[target.name] = "denied-or-error"
        for target in targets:
            if object_exists(target, BASELINE):
                target.call("-n", NS_WORK, "wait", "--for=condition=Available",
                            f"deployment/{BASELINE}", "--timeout=75s", timeout=85)
        red = {name: state == "created" for name, state in baseline_results.items()}
        red["both_baseline_workloads_ready"] = all(object_exists(t, BASELINE) for t in targets)
        lab.check("red", "Unchecked posture permits the harmless baseline on both owned members",
                  all(red.values()), red)

        candidate_obj = candidate(CANDIDATE)
        candidate_hash = digest(candidate_obj)
        unsafe = unsafe_probe(candidate_obj)
        observed = {}
        policies = {}
        for target in targets:
            policies[target.name] = install_posture_control(target)
            safe = admission_result(target, candidate_obj)
            desired = "denied-by-policy" if target.name == "hub" else "accepted"
            unsafe_result = await_posture(lab, target, unsafe, desired)
            uid = identities[target.name]["uid"]
            receipt = {
                "schema": "saf-k8s-0910-018/posture-receipt-v1",
                "member_uid": uid,
                "api_endpoint": identities[target.name]["endpoint"],
                "candidate_namespace": NS_WORK,
                "candidate_name": CANDIDATE,
                "candidate_sha256": candidate_hash,
                "policy": policies[target.name],
                "nodes_ready": ready_nodes(target),
                "safe_admission": safe,
                "unsafe_probe": unsafe_result,
                "observed_at_epoch": int(time.time()),
                "observer": OBSERVER,
            }
            receipt["receipt_sha256"] = digest(receipt)
            write_claim(target, EVIDENCE, receipt, OBSERVER)
            observed[target.name] = receipt

        healthy = targets[0]
        healthy_uid = identities[healthy.name]["uid"]
        healthy_policy = policies[healthy.name]
        canonical_receipt = observed[healthy.name]
        failures = {}
        # Challenge the placement gate with API-backed malformed or expired records.
        stale = dict(canonical_receipt)
        stale["observed_at_epoch"] = int(time.time()) - MAX_AGE_SECONDS - 5
        stale["receipt_sha256"] = digest({k: v for k, v in stale.items() if k != "receipt_sha256"})
        for label, trial in (
            ("missing", None),
            ("stale", stale),
            ("wrong_member", {**canonical_receipt, "member_uid": identities["peer"]["uid"]}),
        ):
            if trial is not None and trial.get("receipt_sha256") != digest(
                    {k: v for k, v in trial.items() if k != "receipt_sha256"}):
                trial["receipt_sha256"] = digest({k: v for k, v in trial.items()
                                                   if k != "receipt_sha256"})
            set_trial_claim(healthy, trial)
            result = place_if_eligible(healthy, candidate_obj, candidate_hash,
                                       healthy_uid, healthy_policy)
            failures[label] = {"decision": result["decision"], "reason": result["reason"],
                               "no_workload_created": not object_exists(healthy, CANDIDATE)}
        set_trial_claim(healthy, canonical_receipt)
        no_approval = place_if_eligible(healthy, candidate_obj, candidate_hash, healthy_uid, healthy_policy)
        alternate = targets[1]
        weak = place_if_eligible(alternate, candidate_obj, candidate_hash, identities["peer"]["uid"],
                                 policies["peer"])
        wrong_workload = place_if_eligible(healthy, baseline_obj, candidate_hash, healthy_uid, healthy_policy)
        failures["missing_approval"] = {**no_approval,
            "no_workload_created": not object_exists(healthy, CANDIDATE)}
        failures["warn_only_member"] = {**weak,
            "no_workload_created": not object_exists(alternate, CANDIDATE)}
        failures["changed_workload"] = {**wrong_workload,
            "no_workload_created": not object_exists(healthy, CANDIDATE)}
        expected_reasons = {
            "missing": "missing-evidence", "stale": "stale-evidence",
            "wrong_member": "evidence-binding-or-enforcement-mismatch",
            "missing_approval": "approval-missing-or-mismatched",
            "warn_only_member": "evidence-binding-or-enforcement-mismatch",
            "changed_workload": "workload-digest-mismatch",
        }
        green = {
            "live_member_specific_posture": all(r["safe_admission"]["decision"] == "accepted" and r["nodes_ready"]
                                                 for r in observed.values())
                and observed["hub"]["unsafe_probe"]["decision"] == "denied-by-policy"
                and observed["peer"]["unsafe_probe"]["decision"] == "accepted",
            "all_ineligible_requests_fail_closed_for_the_expected_reasons": all(
                row["decision"] == "blocked" and row["no_workload_created"]
                and row["reason"] == expected_reasons[name] for name, row in failures.items()),
            "receipt_identity_is_per_member": observed["hub"]["member_uid"] != observed["peer"]["member_uid"],
            "observation_approval_and_action_are_separate": (
                forbidden_patch(healthy, actor(OBSERVER), APPROVAL)
                and forbidden_patch(healthy, actor(APPROVER), EVIDENCE)
                and forbidden_patch(healthy, actor(PLACER), EVIDENCE)
                and forbidden_patch(healthy, actor(PLACER), APPROVAL)),
        }
        lab.check("green", "Posture evidence is live, exact-member bound, fresh, and required",
                  all(green.values()), {"enforcement": {
                      name: {"safe": r["safe_admission"], "unsafe": r["unsafe_probe"]}
                      for name, r in observed.items()}, "fail_closed_trials": failures, "checks": green})

        # A distinct reviewer approves the exact evidence digest; placement re-reads both records.
        approval = approval_record(candidate_hash, healthy_uid)
        approval["evidence_sha256"] = canonical_receipt["receipt_sha256"]
        write_claim(healthy, APPROVAL, approval, APPROVER)
        readback = claim(healthy, APPROVAL)
        approved = (readback == approval and readback.get("reviewer") == APPROVER
                    and APPROVER != OBSERVER and APPROVER != PLACER)
        placement = (place_if_eligible(healthy, candidate_obj, candidate_hash,
                                       healthy_uid, healthy_policy) if approved else
                     {"decision": "blocked", "reason": "approval-readback-mismatch", "created": False})
        if placement.get("decision") == "placed":
            healthy.call("-n", NS_WORK, "wait", "--for=condition=Available",
                         f"deployment/{CANDIDATE}", "--timeout=75s", timeout=85)
        positive = {
            "separate_reviewer_approved_exact_receipt": approved,
            "healthy_member_received_real_create": placement.get("decision") == "placed",
            "candidate_reached_available": object_exists(healthy, CANDIDATE),
        }
        lab.check("positive", "Fresh reviewed posture permits real placement on the healthy member",
                  all(positive.values()), {"member": healthy.name, "placement": placement,
                                           "checks": positive})

        next_obj = candidate(REEVALUATION_CANDIDATE)
        next_hash = digest(next_obj)
        next_receipt = {
            **canonical_receipt, "candidate_name": REEVALUATION_CANDIDATE,
            "candidate_sha256": next_hash, "observed_at_epoch": int(time.time()),
            "safe_admission": admission_result(healthy, next_obj),
            "unsafe_probe": admission_result(healthy, unsafe_probe(next_obj)),
            "nodes_ready": ready_nodes(healthy),
        }
        next_receipt.pop("receipt_sha256")
        next_receipt["receipt_sha256"] = digest(next_receipt)
        write_claim(healthy, EVIDENCE, next_receipt, OBSERVER)
        next_approval = approval_record(next_hash, healthy_uid)
        next_approval["evidence_sha256"] = next_receipt["receipt_sha256"]
        write_claim(healthy, APPROVAL, next_approval, APPROVER)
        eligible_before_drift = check_eligibility(
            healthy, next_hash, healthy_uid, healthy_policy,
            candidate_name=REEVALUATION_CANDIDATE)

        # Re-evaluate a later, distinct candidate against the live policy binding.
        # Keep Deny active; the metadata change represents a changed target posture
        # identity, not a weakened admission policy or an existing-workload action.
        original_binding = healthy.json(
            "get", "validatingadmissionpolicybinding", POLICY, "-o", "json")
        healthy.call(
            "patch", "validatingadmissionpolicybinding", POLICY,
            "--type=merge",
            "-p", json.dumps({"spec": {"validationActions": ["Deny", "Audit"]}}))
        changed_binding = healthy.json(
            "get", "validatingadmissionpolicybinding", POLICY, "-o", "json")
        changed_policy_id = {
            "name": POLICY,
            "uid": healthy.json("get", "validatingadmissionpolicy", POLICY,
                                "-o", "json").get("metadata", {}).get("uid"),
            "spec_sha256": digest(healthy.json(
                "get", "validatingadmissionpolicy", POLICY, "-o", "json").get("spec", {})),
            "binding_uid": changed_binding.get("metadata", {}).get("uid"),
            "binding_spec_sha256": digest(changed_binding.get("spec", {})),
            "failure_policy": "Fail",
        }
        post_change_unsafe = admission_result(healthy, unsafe_probe(next_obj))
        reevaluation_placement = place_if_eligible(
            healthy, next_obj, next_hash, healthy_uid, healthy_policy)
        prior_workload_remains = (
            object_exists(healthy, CANDIDATE)
            and healthy.kube("-n", NS_WORK, "wait", "--for=condition=Available",
                             f"deployment/{CANDIDATE}", "--timeout=10s",
                             timeout=15).returncode == 0)
        reevaluation = {
            "exact_later_candidate_was_eligible_before_drift":
                eligible_before_drift == (True, "eligible"),
            "binding_changed": (
                changed_policy_id["binding_uid"] == original_binding.get("metadata", {}).get("uid")
                and changed_policy_id["binding_spec_sha256"]
                != digest(original_binding.get("spec", {}))
                and changed_binding.get("spec", {}).get("validationActions") == ["Deny", "Audit"]),
            "deny_action_preserved": "Deny" in changed_binding.get("spec", {}).get("validationActions", []),
            "native_policy_still_denies_unsafe_candidate": (
                post_change_unsafe.get("decision") == "denied-by-policy"
                and post_change_unsafe.get("signal") == DENIAL),
            "second_candidate_blocked_for_live_policy_drift": (
                reevaluation_placement.get("decision") == "blocked"
                and reevaluation_placement.get("reason") == "live-policy-identity-mismatch"),
            "second_candidate_absent": not object_exists(healthy, REEVALUATION_CANDIDATE),
            "previous_approved_workload_remains_available": prior_workload_remains,
        }
        lab.check("reevaluation", "Live policy identity drift blocks a later placement while preserving the approved workload",
                  all(reevaluation.values()), {
                      "member": healthy.name,
                      "candidate_sha256": next_hash,
                      "unsafe_server_dry_run": post_change_unsafe,
                      "placement": reevaluation_placement,
                      "checks": reevaluation,
                  })

        normalized = {
            "control": "SAF-K8S-0910-018", "schema": "posture-placement-v1",
            "scope": SCOPE, "members": identities, "candidate_sha256": candidate_hash,
            "policy": policies, "baseline_unchecked": red,
            "enforcement": {name: {"safe": r["safe_admission"],
                                    "unsafe": r["unsafe_probe"],
                                    "receipt_sha256": r["receipt_sha256"]}
                            for name, r in observed.items()},
            "fail_closed": failures, "approved_placement": positive,
            "post_placement_reevaluation": reevaluation,
            "exact_receipts": observed, "exact_approval": readback,
            "freshness_bound_seconds": MAX_AGE_SECONDS,
        }
        (lab.evidence / "posture-placement-normalized.json").write_text(json.dumps({
            "candidate_sha256": candidate_hash, "baseline": red, "posture": green,
            "fail_closed": failures, "approved_placement": positive,
            "post_placement_reevaluation": reevaluation,
        }, indent=2, sort_keys=True) + "\n")
        (lab.evidence / "saf-k8s-0910-018-posture-placement.json").write_text(
            json.dumps(normalized, sort_keys=True, indent=2) + "\n")
