"""Audit additive RBAC grants for a synthetic ServiceAccount using SAR."""
import json
import importlib.util
from pathlib import Path
import time

HERE = Path(__file__).parent
NAMESPACE = "saf-0401-002"
REVIEW_NAMESPACE = "saf-0401-002-review"
SERVICE_ACCOUNT = "saf-0401-002-audited-reader"
SUBJECT = f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT}"
GROUPS = [
    "system:serviceaccounts",
    f"system:serviceaccounts:{NAMESPACE}",
    "system:authenticated",
]
REQUIRED = "saf-0401-002-required-config"
UNNEEDED = "saf-0401-002-unneeded-config"
REQUIRED_ROLE = "saf-0401-002-required-reader"
UNNEEDED_ROLE = "saf-0401-002-unneeded-reader"
UNNEEDED_BINDING = "saf-0401-002-unneeded-reader"

SCOPE = (
    "Kubernetes v1.36.1 RBAC inventory bounded to objects carrying this case's "
    "label, plus SubjectAccessReviews for two synthetic subjects, two fixture "
    "namespaces, and named ConfigMap get/patch tuples. Inventory is not treated "
    "as effective authorization: each matrix cell is evaluated by the API "
    "server. A deliberately excessive RoleBinding is removed. A synthetic "
    "CronJob submits only fixed SelfSubjectAccessReviews for two named benign "
    "ConfigMaps. No real subjects, data, credentials, or escalation paths are used."
)


def named_review(name, namespace=NAMESPACE, verb="get", user=SUBJECT, groups=GROUPS):
    return {
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SubjectAccessReview",
        "spec": {
            "user": user,
            "groups": groups,
            "resourceAttributes": {
                "namespace": namespace,
                "verb": verb,
                "group": "",
                "resource": "configmaps",
                "name": name,
            },
        },
    }


def review(lab, name, namespace=NAMESPACE, verb="get", user=SUBJECT, groups=GROUPS):
    result = lab.kubectl(
        "create", "-f", "-", "-o", "json",
        payload=json.dumps(named_review(name, namespace, verb, user, groups)),
    )
    response = json.loads(result.stdout)
    status = response["status"]
    if status.get("evaluationError"):
        raise RuntimeError(f"SubjectAccessReview evaluation failed: {status['evaluationError']}")
    return {
        "allowed": status.get("allowed", False),
        "denied": status.get("denied", False),
        "reason": status.get("reason", ""),
    }


def role_rules(lab, name):
    result = lab.kubectl("-n", NAMESPACE, "get", "role", name, "-o", "json")
    return json.loads(result.stdout).get("rules", [])


def named_get_rule(configmap):
    return [{
        "apiGroups": [""],
        "resources": ["configmaps"],
        "resourceNames": [configmap],
        "verbs": ["get"],
    }]


def named_get_patch_rule(configmap):
    return [{"apiGroups": [""], "resources": ["configmaps"],
             "resourceNames": [configmap], "verbs": ["get", "patch"]}]


def case_inventory(lab, kind, namespace=None, all_namespaces=False):
    args = ["get", kind]
    if all_namespaces:
        args.append("--all-namespaces")
    elif namespace:
        args[0:0] = ["-n", namespace]
    args += ["-l", "saf-k8s.example/control-case=SAF-K8S-0401-002", "-o", "json"]
    return json.loads(lab.kubectl(*args).stdout).get("items", [])


def inventory_summary(lab):
    return {
        "roles": sorted(x["metadata"]["name"] for x in case_inventory(lab, "roles", all_namespaces=True)),
        "clusterroles": sorted(x["metadata"]["name"] for x in case_inventory(lab, "clusterroles")),
        "rolebindings": sorted(x["metadata"]["name"] for x in case_inventory(lab, "rolebindings", all_namespaces=True)),
        "clusterrolebindings": sorted(x["metadata"]["name"] for x in case_inventory(lab, "clusterrolebindings")),
    }


def cluster_role_matches(lab):
    body = json.loads(lab.kubectl("get", "clusterrole", "saf-0401-002-cross-namespace-reader", "-o", "json").stdout)
    return body.get("rules", []) == named_get_rule(REQUIRED)


def cluster_binding_matches(lab):
    body = json.loads(lab.kubectl("get", "clusterrolebinding", "saf-0401-002-cross-namespace-reader", "-o", "json").stdout)
    return (
        body.get("roleRef") == {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                                 "name": "saf-0401-002-cross-namespace-reader"}
        and body.get("subjects") == [{"kind": "ServiceAccount", "name": SERVICE_ACCOUNT,
                                      "namespace": NAMESPACE}]
    )


def matrix_review(lab, subject, namespace, verb, name):
    return review(lab, name, namespace, verb, subject,
                  GROUPS if subject == SUBJECT else ["system:authenticated"])


def binding_exists(lab, name):
    result = lab.kubectl(
        "-n", NAMESPACE, "get", "rolebinding", name,
        "-o", "name", allow_failure=True,
    )
    return result.returncode == 0 and result.stdout.strip() == f"rolebinding.rbac.authorization.k8s.io/{name}"


def binding_matches(lab, binding, role):
    result = lab.kubectl("-n", NAMESPACE, "get", "rolebinding", binding, "-o", "json")
    body = json.loads(result.stdout)
    return (
        body.get("roleRef") == {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": role,
        }
        and body.get("subjects") == [{
            "kind": "ServiceAccount",
            "name": SERVICE_ACCOUNT,
            "namespace": NAMESPACE,
        }]
    )


def wait_for_remediated_decisions(lab, timeout=10):
    deadline = time.monotonic() + timeout
    while True:
        required = review(lab, REQUIRED)
        unneeded = review(lab, UNNEEDED)
        if required["allowed"] and not unneeded["allowed"]:
            return required, unneeded
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "SubjectAccessReview decisions did not reflect the binding removal "
                f"within {timeout}s: required={required}; unneeded={unneeded}"
            )
        time.sleep(0.2)


def check_unapplied_rule_inventory(lab):
    fixture = json.loads((HERE / "manifest_inventory_fixture.json").read_text())
    spec = importlib.util.spec_from_file_location("manifest_inventory", HERE / "manifest_inventory.py")
    inventory = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inventory)
    result = inventory.evaluate(fixture)
    observed = result["baseline"]["findings"]
    expected = [
        ("fixture-sensitive-rule-candidate", ["authorization-sensitive-verbs"]),
        ("fixture-wildcard-candidate", ["wildcard-verbs"]),
    ]
    reconciled = result["reconciled"]
    inert = all(row["kind"] in ("Role", "ClusterRole") and not row.get("subjects")
                for row in fixture["objects"])
    exact = [(row["object_name"], row["categories"]) for row in observed] == expected
    exact = exact and observed[0]["sensitive_verbs"] == ["bind", "escalate", "impersonate"]
    retained = [row["name"] for row in reconciled["objects"]] == ["fixture-required-read"]
    isolated = all(row["effective_authorization"] == "not_evaluated" for row in observed)
    lab.check("green", "An offline inventory flags exactly two unbound rule definitions and preserves the required named read",
              inert and exact and retained and isolated and not reconciled["findings"],
              {"matched_candidates": observed, "only_required_definition_retained": retained,
               "fixture_has_no_bindings": inert, "no_candidate_rules_after_reconciliation": not reconciled["findings"]})


def run(lab):
    check_unapplied_rule_inventory(lab)
    # The fresh cluster is isolated; every object in this manifest is case-owned.
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("create", "namespace", REVIEW_NAMESPACE)
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "fixtures.yaml"))

    lab.kubectl("-n", REVIEW_NAMESPACE, "apply", "-f", str(HERE / "review-fixture.yaml"))

    declared_required = role_rules(lab, REQUIRED_ROLE)
    declared_unneeded = role_rules(lab, UNNEEDED_ROLE)
    required_binding_matches = binding_matches(lab, REQUIRED_ROLE, REQUIRED_ROLE)
    unneeded_binding_matches = binding_matches(lab, UNNEEDED_BINDING, UNNEEDED_ROLE)
    required_before = review(lab, REQUIRED)
    unneeded_before = review(lab, UNNEEDED)
    inventory = inventory_summary(lab)
    matrix_before = {
        "required_get_home": matrix_review(lab, SUBJECT, NAMESPACE, "get", REQUIRED),
        "required_get_review_namespace": matrix_review(lab, SUBJECT, REVIEW_NAMESPACE, "get", REQUIRED),
        "unneeded_get_home": matrix_review(lab, SUBJECT, NAMESPACE, "get", UNNEEDED),
        "unneeded_patch_home": matrix_review(lab, SUBJECT, NAMESPACE, "patch", UNNEEDED),
        "required_patch_home": matrix_review(lab, SUBJECT, NAMESPACE, "patch", REQUIRED),
        "unbound_synthetic_get": matrix_review(lab, "saf-k8s:0401-002:unbound-reviewer", NAMESPACE, "get", REQUIRED),
    }

    lab.check(
        "red",
        "The declared narrow Role and extra named-read Role combine additively; the audit detects the unnecessary read",
        declared_required == named_get_rule(REQUIRED)
        and declared_unneeded == named_get_patch_rule(UNNEEDED)
        and inventory == {
            "roles": sorted([REQUIRED_ROLE, UNNEEDED_ROLE]),
            "clusterroles": ["saf-0401-002-cross-namespace-reader"],
            "rolebindings": sorted([REQUIRED_ROLE, UNNEEDED_BINDING]),
            "clusterrolebindings": ["saf-0401-002-cross-namespace-reader"],
        }
        and cluster_role_matches(lab)
        and cluster_binding_matches(lab)
        and binding_exists(lab, REQUIRED_ROLE)
        and binding_exists(lab, UNNEEDED_BINDING)
        and required_binding_matches
        and unneeded_binding_matches
        and required_before["allowed"]
        and unneeded_before["allowed"]
        and matrix_before["required_get_home"]["allowed"]
        and matrix_before["required_get_review_namespace"]["allowed"]
        and matrix_before["unneeded_get_home"]["allowed"]
        and matrix_before["unneeded_patch_home"]["allowed"]
        and not matrix_before["required_patch_home"]["allowed"]
        and not matrix_before["unbound_synthetic_get"]["allowed"],
        {
            "required_role_rules": declared_required,
            "unneeded_role_rules": declared_unneeded,
            "required_binding_matches": required_binding_matches,
            "unneeded_binding_matches": unneeded_binding_matches,
            "cluster_role_matches": cluster_role_matches(lab),
            "cluster_role_binding_matches": cluster_binding_matches(lab),
            "required_named_get": required_before,
            "unneeded_named_get": unneeded_before,
            "both_bindings_present": True,
            "case_owned_inventory": inventory,
            "authorization_matrix_before": matrix_before,
        },
    )

    # Follow the real periodic controller across a recorded gap, a minimal
    # binding change, and a later scheduled confirmation.
    recurrence_spec = importlib.util.spec_from_file_location("recurrence_case", HERE / "recurrence.py")
    recurrence_case = importlib.util.module_from_spec(recurrence_spec)
    recurrence_spec.loader.exec_module(recurrence_case)
    recurrence_case.run(lab)

    required_after, unneeded_after = wait_for_remediated_decisions(lab)
    matrix_after = {
        "required_get_home": matrix_review(lab, SUBJECT, NAMESPACE, "get", REQUIRED),
        "required_get_review_namespace": matrix_review(lab, SUBJECT, REVIEW_NAMESPACE, "get", REQUIRED),
        "unneeded_get_home": matrix_review(lab, SUBJECT, NAMESPACE, "get", UNNEEDED),
        "unneeded_patch_home": matrix_review(lab, SUBJECT, NAMESPACE, "patch", UNNEEDED),
        "required_patch_home": matrix_review(lab, SUBJECT, NAMESPACE, "patch", REQUIRED),
        "unbound_synthetic_get": matrix_review(lab, "saf-k8s:0401-002:unbound-reviewer", NAMESPACE, "get", REQUIRED),
    }
    required_binding_after = binding_exists(lab, REQUIRED_ROLE)
    unneeded_binding_after = binding_exists(lab, UNNEEDED_BINDING)
    lab.check(
        "green",
        "Removing the identified case-only binding denies the unnecessary named read while retaining the required read grant",
        required_after["allowed"]
        and not unneeded_after["allowed"]
        and matrix_after["required_get_home"]["allowed"]
        and matrix_after["required_get_review_namespace"]["allowed"]
        and not matrix_after["unneeded_get_home"]["allowed"]
        and not matrix_after["unneeded_patch_home"]["allowed"]
        and not matrix_after["required_patch_home"]["allowed"]
        and not matrix_after["unbound_synthetic_get"]["allowed"]
        and required_binding_after
        and not unneeded_binding_after,
        {
            "required_named_get": required_after,
            "unneeded_named_get": unneeded_after,
            "required_binding_remains": required_binding_after,
            "unneeded_binding_removed": not unneeded_binding_after,
            "authorization_matrix_after": matrix_after,
            "case_owned_inventory_after": inventory_summary(lab),
            "review_decision": {
                "finding": "unnecessary named ConfigMap get and patch",
                "decision": "remove the case-owned unneeded-reader RoleBinding",
                "retained_access": "named get on required ConfigMap in both fixture namespaces",
            },
        },
    )

    # Confirm that the authorization decision corresponds to the actual named GET.
    markers = {}
    for ns, expected in ((NAMESPACE, "required-fixture"), (REVIEW_NAMESPACE, "second-namespace-fixture")):
        subject_args = ["--as", SUBJECT, *(f"--as-group={group}" for group in GROUPS)]
        result = lab.kubectl("-n", ns, *subject_args, "get", f"configmap/{REQUIRED}",
                             "-o", "jsonpath={.data.marker}", allow_failure=True)
        markers[ns] = result.returncode == 0 and result.stdout == expected
    lab.check("positive", "Actual named reads return the expected marker in both audited namespaces",
              all(markers.values()), {"named_reads_preserved": markers})
