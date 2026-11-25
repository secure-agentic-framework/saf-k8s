"""Exercise additive grants, review drift and validate a scoped admission policy."""
from pathlib import Path
import json
import time

HERE = Path(__file__).parent
NS = "saf-0401-001"
OUTSIDE_NS = "saf-0401-001-outside"
USER = "system:serviceaccount:saf-0401-001:saf-0401-001-reader"
GROUP = "saf-k8s.example:0401-001-reviewers"
AGG_GROUP = "saf-k8s.example:0401-001-aggregated-reviewers"
TARGET = "saf-0401-001-required-config"
OTHER = "saf-0401-001-unneeded-config"


def authz(lab, verb, name, namespace=NS, groups=()):
    args = ["auth", "can-i", verb, f"configmap/{name}", "-n", namespace,
            "--as", USER]
    for group in groups:
        args.extend(("--as-group", group))
    return lab.kubectl(*args, allow_failure=True)


def allowed(result):
    return result.returncode == 0 and result.stdout.strip().lower() == "yes"


def denied(result):
    # `can-i` is a SelfSubjectAccessReview: `no` means no authorizer granted
    # this exact verb/resource/name/namespace tuple. Keep output for evidence.
    return result.returncode == 1 and result.stdout.strip().lower() == "no"


def wait_for_aggregation(lab):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        rules = json.loads(lab.kubectl("get", "clusterrole",
            "saf-0401-001-aggregate", "-o", "json").stdout).get("rules", [])
        if any(rule.get("resourceNames") == [TARGET] for rule in rules):
            return True
        time.sleep(1)
    return False


def run(lab):
    # 1. Group grants add to direct grants. The direct Role still allows TARGET;
    #    the synthetic group Role permits OTHER only while its binding exists.
    lab.kubectl("-n", NS, "apply", "-f", str(HERE / "group-grant.yaml"))
    group_other = authz(lab, "get", OTHER, groups=(GROUP,))
    group_target = authz(lab, "get", TARGET, groups=(GROUP,))
    lab.check("red", "A synthetic group binding adds only its named ConfigMap read",
              allowed(group_other) and allowed(group_target),
              {"group_extra_get_yes": group_other.stdout.strip(),
               "direct_required_get_yes": group_target.stdout.strip()})
    lab.kubectl("-n", NS, "delete", "rolebinding", "saf-0401-001-group-extra")
    after_group_revoke = authz(lab, "get", OTHER, groups=(GROUP,))
    target_after_revoke = authz(lab, "get", TARGET, groups=(GROUP,))
    lab.check("green", "Revoking the additive binding removes only its extra grant",
              denied(after_group_revoke) and allowed(target_after_revoke),
              {"unneeded_get_no_reason": "no matching grant after binding removal",
               "required_get_yes": target_after_revoke.stdout.strip()})

    # 2. ClusterRole aggregation plus a ClusterRoleBinding. Rules are limited
    #    to one ConfigMap name. A ClusterRoleBinding still makes that name
    #    readable in every namespace, which the test detects without reading it.
    lab.kubectl("apply", "-f", str(HERE / "cluster-aggregation.yaml"))
    aggregation_ready = wait_for_aggregation(lab)
    agg_target = authz(lab, "get", TARGET, groups=(AGG_GROUP,))
    agg_other = authz(lab, "get", OTHER, groups=(AGG_GROUP,))
    agg_outside = authz(lab, "get", TARGET,
                        namespace=OUTSIDE_NS, groups=(AGG_GROUP,))
    lab.check("red", "Aggregated ClusterRoleBinding resolves the exact namespaced read",
              aggregation_ready and allowed(agg_target) and denied(agg_other)
              and allowed(agg_outside),
              {"aggregation_controller_copied_rule": aggregation_ready,
               "required_named_get_yes": agg_target.stdout.strip(),
               "unrelated_name_no_reason": "no matching resourceName rule",
               "cluster_binding_cross_namespace_get_yes": agg_outside.stdout.strip(),
               "scope_note": "ClusterRoleBinding applies the ClusterRole in every namespace"})
    lab.kubectl("delete", "clusterrolebinding", "saf-0401-001-aggregated")
    outside_after_revoke = authz(lab, "get", TARGET, namespace=OUTSIDE_NS,
                                 groups=(AGG_GROUP,))
    target_after_revoke = authz(lab, "get", TARGET, groups=(AGG_GROUP,))
    lab.check("green", "Removing the cluster binding restores namespace denial",
              denied(outside_after_revoke) and allowed(target_after_revoke),
              {"outside_named_get_no_reason": "no matching grant after ClusterRoleBinding removal",
               "required_named_get_yes": target_after_revoke.stdout.strip()})
    lab.kubectl("delete", "clusterrole", "saf-0401-001-aggregate")
    lab.kubectl("delete", "clusterrole", "saf-0401-001-child")

    # 3. Source-of-truth review: compare live Role rules to the approved
    #    manifest; detect one benign extra named read, then restore the source.
    if lab.kubectl("-n", NS, "diff", "-f", str(HERE / "least-privilege.yaml"), allow_failure=True).returncode:
        lab.block("The live baseline differs from the reviewed narrow manifest")
    approved = json.loads(lab.kubectl("-n", NS, "get", "role",
        "saf-0401-001-required-config-reader", "-o", "json").stdout)["rules"]
    changed = json.loads(json.dumps(approved))
    changed.append({"apiGroups": [""], "resources": ["configmaps"],
                    "resourceNames": [OTHER], "verbs": ["get"]})
    lab.kubectl("-n", NS, "patch", "role", "saf-0401-001-required-config-reader",
                "--type=merge", "-p", json.dumps({"rules": changed}))
    drift_rules = json.loads(lab.kubectl("-n", NS, "get", "role",
        "saf-0401-001-required-config-reader", "-o", "json").stdout)["rules"]
    drift_access = authz(lab, "get", OTHER)
    source_diff = lab.kubectl("-n", NS, "diff", "-f", str(HERE / "least-privilege.yaml"),
                              allow_failure=True)
    lab.check("red", "Source review finds an added benign named read",
              drift_rules != approved and allowed(drift_access)
              and source_diff.returncode == 1,
              {"source_rules_differ": drift_rules != approved,
               "manifest_diff_detected": source_diff.returncode == 1,
               "extra_named_get_yes": drift_access.stdout.strip()})
    lab.kubectl("-n", NS, "apply", "-f", str(HERE / "least-privilege.yaml"))
    restored_rules = json.loads(lab.kubectl("-n", NS, "get", "role",
        "saf-0401-001-required-config-reader", "-o", "json").stdout)["rules"]
    revoked_access = authz(lab, "get", OTHER)
    required_access = authz(lab, "get", TARGET)
    clean_diff = lab.kubectl("-n", NS, "diff", "-f", str(HERE / "least-privilege.yaml"),
                             allow_failure=True)
    lab.check("green", "Approved source restoration revokes the extra read",
              restored_rules == approved and denied(revoked_access) and allowed(required_access)
              and clean_diff.returncode == 0,
              {"rules_match_approved_source": restored_rules == approved,
               "manifest_diff_clear": clean_diff.returncode == 0,
               "extra_named_get_no_reason": "no matching RBAC grant after restoration",
               "required_named_get_yes": required_access.stdout.strip()})

    # 4. Admission policy check uses server-side dry-run. The wildcard Role
    #    is never bound; the exact named-read comparison should be admitted.
    check_role = ("apply", "--dry-run=server", "-f", str(HERE / "overbroad-role.yaml"))
    baseline = lab.kubectl("-n", NS, *check_role, allow_failure=True)
    lab.check("red", "An unbound wildcard Role passes server dry-run before the fixture policy",
              baseline.returncode == 0, {"wildcard_role_admitted_before_policy": baseline.returncode == 0})
    lab.kubectl("label", "namespace", NS,
                "saf-k8s.example/control-case=SAF-K8S-0401-001", "--overwrite")
    lab.kubectl("apply", "-f", str(HERE / "scoped-admission.yaml"))
    deadline = time.monotonic() + 20
    message = "wildcard verbs or resources are not allowed in the SAF-K8S-0401-001 fixture namespace"
    while True:
        rejected = lab.kubectl("-n", NS, *check_role, allow_failure=True)
        intended_denial = (rejected.returncode != 0 and message in rejected.stderr
                           and "saf-0401-001-no-wildcard-rbac" in rejected.stderr)
        if intended_denial or time.monotonic() >= deadline:
            break
        time.sleep(0.4)
    positive = lab.kubectl("-n", NS, "apply", "--dry-run=server", "-f",
                           str(HERE / "least-privilege.yaml"), allow_failure=True)
    outside = lab.kubectl("-n", OUTSIDE_NS, *check_role, allow_failure=True)
    lab.check("green", "Admission rejects the wildcard in the selected namespace and preserves the permitted cases",
              intended_denial and positive.returncode == 0 and outside.returncode == 0,
              {"overbroad_role_denied_by_policy": intended_denial,
               "approved_role_dry_run_admitted": positive.returncode == 0,
               "unselected_namespace_unaffected": outside.returncode == 0})
    lab.kubectl("delete", "-f", str(HERE / "scoped-admission.yaml"))
