"""Review synthetic ML, platform and security RBAC boundaries with live Pod tokens."""
import json
from pathlib import Path

from fixtures import container, pod


HERE = Path(__file__).parent
NAMESPACE = "saf-0401-006"
FUNCTIONS = ("ml", "platform", "security")
IDENTITIES = {
    name: f"saf-0401-006-{name}" for name in (*FUNCTIONS, "admin-check")
}
PODS = {name: f"saf-0401-006-{name}-pod" for name in IDENTITIES}
OPERATIONS = ("model-read", "platform-dry-run-patch", "audit-read")
EXPECTED = {
    "ml": "model-read",
    "platform": "platform-dry-run-patch",
    "security": "audit-read",
}
SCOPE = (
    "Kubernetes v1.36.1 native namespaced RBAC in one disposable kind cluster. "
    "Three independent synthetic ServiceAccounts use their actual projected Pod "
    "tokens to GET one inert named ConfigMap or send a server-side dry-run PATCH "
    "to one inert named ConfigMap. The case compares all three operations before "
    "and after exact RoleBindings and includes a fourth bounded admin-check "
    "ServiceAccount. A temporary negative-control binding demonstrates additive "
    "permission overlap and is removed before the case completes. The overlap "
    "oracle is fixture-only. It does not validate IdP group mapping, organization "
    "approval, role ownership, production access, AI operator CRDs, or cluster-wide grants."
)


def make_pod(function, service_account):
    fixture = pod(
        PODS[function],
        [container(
            "probe", image="docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90",
            command=["python", "-c", "import time; time.sleep(3600)"],
            volumeMounts=[{"name": "probe", "mountPath": "/fixture", "readOnly": True}],
            securityContext={"allowPrivilegeEscalation": False,
                             "capabilities": {"drop": ["ALL"]},
                             "runAsNonRoot": True, "runAsUser": 65534,
                             "readOnlyRootFilesystem": True,
                             "seccompProfile": {"type": "RuntimeDefault"}},
        )],
        serviceAccountName=service_account,
        automountServiceAccountToken=True,
        volumes=[{"name": "probe", "configMap": {"name": "saf-0401-006-probe"}}],
    )
    fixture["metadata"]["labels"] = {
        "saf-k8s.example/control": "SAF-K8S-0401-006",
        "saf-k8s.example/function": function,
    }
    return fixture


def decisions(lab, function):
    output = lab.kubectl(
        "-n", NAMESPACE, "exec", PODS[function], "--", "python", "/fixture/probe.py",
    ).stdout.strip()
    return json.loads(output)


def observed_pod_identities(lab):
    observed = {}
    for function, pod_name in PODS.items():
        obj = json.loads(lab.kubectl(
            "-n", NAMESPACE, "get", "pod", pod_name, "-o", "json",
        ).stdout)
        observed[function] = {
            "service_account": obj.get("spec", {}).get("serviceAccountName"),
            "automount_token": obj.get("spec", {}).get("automountServiceAccountToken", True),
        }
    return observed


def rules_match(lab):
    expected = {
        "ml": [{"apiGroups": [""], "resources": ["configmaps"],
                "resourceNames": ["saf-0401-006-model-fixture"], "verbs": ["get"]}],
        "platform": [{"apiGroups": [""], "resources": ["configmaps"],
                      "resourceNames": ["saf-0401-006-platform-fixture"], "verbs": ["patch"]}],
        "security": [{"apiGroups": [""], "resources": ["configmaps"],
                      "resourceNames": ["saf-0401-006-security-fixture"], "verbs": ["get"]}],
    }
    observed = {}
    for function in FUNCTIONS:
        role = json.loads(lab.kubectl(
            "-n", NAMESPACE, "get", "role", f"saf-0401-006-{function}-role", "-o", "json",
        ).stdout)
        binding = json.loads(lab.kubectl(
            "-n", NAMESPACE, "get", "rolebinding", f"saf-0401-006-{function}-binding", "-o", "json",
        ).stdout)
        observed[function] = (
            role.get("rules") == expected[function]
            and binding.get("subjects") == [{"kind": "ServiceAccount",
                                               "name": IDENTITIES[function],
                                               "namespace": NAMESPACE}]
            and binding.get("roleRef") == {
                "apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                "name": f"saf-0401-006-{function}-role",
            }
        )
    return observed


def temporary_overlap_binding():
    """Negative control: give the existing ML fixture identity the platform grant."""
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {
            "name": "saf-0401-006-overlap-negative-control",
            "namespace": NAMESPACE,
            "annotations": {"saf-k8s.example/fixture": "negative-control-only"},
        },
        "subjects": [{
            "kind": "ServiceAccount",
            "name": IDENTITIES["ml"],
            "namespace": NAMESPACE,
        }],
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": "saf-0401-006-platform-role",
        },
    }


def modeled_function_overlap(lab):
    """Fixture-only overlap oracle over the three case-owned functional bindings."""
    resolved = {}
    for function in FUNCTIONS:
        binding = json.loads(lab.kubectl(
            "-n", NAMESPACE, "get", "rolebinding",
            f"saf-0401-006-{function}-binding", "-o", "json",
        ).stdout)
        for subject in binding.get("subjects", []):
            if subject.get("kind") == "ServiceAccount" and subject.get("namespace") == NAMESPACE:
                key = subject["name"]
                resolved.setdefault(key, set()).add(function)

    extra = json.loads(lab.kubectl(
        "-n", NAMESPACE, "get", "rolebinding",
        "saf-0401-006-overlap-negative-control", "-o", "json",
    ).stdout)
    for subject in extra.get("subjects", []):
        if subject.get("kind") == "ServiceAccount" and subject.get("namespace") == NAMESPACE:
            key = subject["name"]
            resolved.setdefault(key, set()).add("platform")

    return {
        identity: sorted(functions)
        for identity, functions in resolved.items()
        if len(functions) > 1
    }


def run(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "fixtures.yaml"))
    probe_map = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "saf-0401-006-probe", "namespace": NAMESPACE},
        "data": {"probe.py": (HERE / "probe.py").read_text()},
    }
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(probe_map))
    for function, service_account in IDENTITIES.items():
        lab.kubectl("-n", NAMESPACE, "create", "-f", "-",
                    payload=json.dumps(make_pod(function, service_account)))
        lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{PODS[function]}",
                    "--timeout=95s", timeout=105)
    pod_identities = observed_pod_identities(lab)
    lab.check(
        "positive", "Three functional Pods use three distinct explicit ServiceAccounts with projected tokens",
        all(pod_identities[function] == {"service_account": IDENTITIES[function],
                                         "automount_token": True}
            for function in FUNCTIONS)
        and len({pod_identities[function]["service_account"] for function in FUNCTIONS}) == 3,
        pod_identities,
    )

    expected_denied = {operation: 403 for operation in OPERATIONS}
    red = {function: decisions(lab, function) for function in (*FUNCTIONS, "admin-check")}
    lab.check(
        "red", "Each functional projected identity is denied all representative fixture operations before binding",
        all(red[function] == expected_denied for function in FUNCTIONS),
        {function: red[function] for function in FUNCTIONS},
    )
    lab.check(
        "positive", "The bounded admin-check identity is also denied before its explicit binding",
        red["admin-check"] == expected_denied, red["admin-check"],
    )

    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "roles-and-bindings.yaml"))
    declaration_results = rules_match(lab)
    lab.check("positive", "Three functional RoleBindings each name one independent ServiceAccount and one exact Role",
              all(declaration_results.values()), declaration_results)

    green = {function: decisions(lab, function) for function in (*FUNCTIONS, "admin-check")}
    expected_green = {
        function: {operation: 200 if operation == EXPECTED[function] else 403
                   for operation in OPERATIONS}
        for function in FUNCTIONS
    }
    lab.check("green", "Each function can perform only its representative inert named operation",
              all(green[function] == expected_green[function] for function in FUNCTIONS),
              {function: green[function] for function in FUNCTIONS})
    admin_expected = {operation: 200 for operation in OPERATIONS}
    lab.check("positive", "The separately bound admin-check fixture can perform all three bounded operations",
              green["admin-check"] == admin_expected, green["admin-check"])

    unchanged = json.loads(lab.kubectl(
        "-n", NAMESPACE, "get", "configmap", "saf-0401-006-platform-fixture", "-o", "json",
    ).stdout)
    dry_run_only = "saf-k8s.example/probe" not in unchanged["metadata"].get("annotations", {})
    lab.check("positive", "Successful platform dry-run changes leave the marker unmodified",
              dry_run_only, {"persistent_annotation_absent": dry_run_only})

    # Deliberately demonstrate the additive grant conflict with one extra
    # case-owned binding. This is a negative control, not evidence that RBAC
    # prevents overlapping functional assignments. Cleanup is unconditional.
    temporary_binding = temporary_overlap_binding()
    try:
        lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(temporary_binding))
        overlap_matrix = decisions(lab, "ml")
        expected_overlap = {
            "model-read": 200,
            "platform-dry-run-patch": 200,
            "audit-read": 403,
        }
        lab.check(
            "negative",
            "One synthetic ML subject with the existing platform binding accumulates both functional grants",
            overlap_matrix == expected_overlap,
            {"observed": overlap_matrix, "expected": expected_overlap},
        )
        observed_overlap = modeled_function_overlap(lab)
        expected_subject = {IDENTITIES["ml"]: ["ml", "platform"]}
        lab.check(
            "negative",
            "The fixture-only binding review flags the deliberate ML/platform subject overlap",
            observed_overlap == expected_subject,
            {"observed_overlap": observed_overlap, "expected_overlap": expected_subject},
        )
        remaining_functional = {
            function: decisions(lab, function)
            for function in ("platform", "security")
        }
        expected_remaining = {
            "platform": {operation: 200 if operation == EXPECTED["platform"] else 403
                         for operation in OPERATIONS},
            "security": {operation: 200 if operation == EXPECTED["security"] else 403
                         for operation in OPERATIONS},
        }
        lab.check(
            "positive",
            "The temporary ML overlap does not change platform or security identity decisions",
            remaining_functional == expected_remaining,
            {"observed": remaining_functional, "expected": expected_remaining},
        )
    finally:
        lab.kubectl(
            "-n", NAMESPACE, "delete", "rolebinding",
            "saf-0401-006-overlap-negative-control", "--ignore-not-found=true",
        )

    restored = decisions(lab, "ml")
    expected_restored = {
        operation: 200 if operation == EXPECTED["ml"] else 403
        for operation in OPERATIONS
    }
    lab.check(
        "positive",
        "Removing the temporary negative-control binding restores the original ML split",
        restored == expected_restored,
        {"observed": restored, "expected": expected_restored},
    )
