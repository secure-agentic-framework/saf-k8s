"""Review distinct AI-workload ServiceAccounts and named-read RBAC via SAR."""
import json
from pathlib import Path
import time

from fixtures import container

HERE = Path(__file__).parent
NAMESPACE = "saf-0402-008"
SHARED_ACCOUNT = "saf-0402-008-shared"
GROUPS = [
    "system:serviceaccounts",
    f"system:serviceaccounts:{NAMESPACE}",
    "system:authenticated",
]
WORKLOADS = {
    "training": {
        "pod": "saf-0402-008-training-workload",
        "service_account": "saf-0402-008-training",
        "configmap": "saf-0402-008-training-data",
        "role": "saf-0402-008-training-reader",
        "binding": "saf-0402-008-training-reader",
    },
    "inference": {
        "pod": "saf-0402-008-inference-workload",
        "service_account": "saf-0402-008-inference",
        "configmap": "saf-0402-008-inference-model",
        "role": "saf-0402-008-inference-reader",
        "binding": "saf-0402-008-inference-reader",
    },
    "pipeline": {
        "pod": "saf-0402-008-pipeline-workload",
        "service_account": "saf-0402-008-pipeline",
        "configmap": "saf-0402-008-pipeline-config",
        "role": "saf-0402-008-pipeline-reader",
        "binding": "saf-0402-008-pipeline-reader",
    },
}
CONFIGMAPS = {workload["configmap"] for workload in WORKLOADS.values()}

SCOPE = (
    "Kubernetes v1.36.1 native ServiceAccounts, Pods, namespaced Roles and "
    "RoleBindings, and three case-owned ConfigMaps. Three ordinary synthetic "
    "Pods begin with a shared account and are recreated with distinct Training, "
    "Inference, and Pipeline accounts. "
    "The case reviews named ConfigMap GET authorization using ephemeral "
    "authorization.k8s.io/v1 SubjectAccessReviews and does not use workload "
    "credentials. A namespace-scoped native admission policy verifies exact type "
    "and ServiceAccount mappings. External cloud IAM, federated identities, "
    "Kubeflow, KServe, training operators, production resources, "
    "and actual model environments are outside this case."
)


def pod_for(kind, values, account):
    result = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": values["pod"],
            "namespace": NAMESPACE,
            "labels": {
                "saf-k8s.example/control-case": "SAF-K8S-0402-008",
                "saf-k8s.example/workload-type": kind,
            },
        },
        "spec": {
            "restartPolicy": "Never",
            "terminationGracePeriodSeconds": 1,
            "serviceAccountName": account,
            "automountServiceAccountToken": False,
            "containers": [container("idle")],
        },
    }
    return result


def named_get_review(username, configmap):
    return {
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SubjectAccessReview",
        "spec": {
            "user": username,
            "groups": GROUPS,
            "resourceAttributes": {
                "namespace": NAMESPACE,
                "verb": "get",
                "group": "",
                "resource": "configmaps",
                "name": configmap,
            },
        },
    }


def review(lab, username, configmap):
    result = lab.kubectl(
        "create", "-f", "-", "-o", "json",
        payload=json.dumps(named_get_review(username, configmap)),
    )
    status = json.loads(result.stdout)["status"]
    if status.get("evaluationError"):
        raise RuntimeError(f"SubjectAccessReview failed: {status['evaluationError']}")
    return {
        "allowed": status.get("allowed", False),
        "denied": status.get("denied", False),
        "reason": status.get("reason", ""),
    }


def inspect_workloads(lab):
    identities = []
    for kind, values in WORKLOADS.items():
        result = lab.kubectl(
            "-n", NAMESPACE, "get", "pod", values["pod"], "-o", "json"
        )
        obj = json.loads(result.stdout)
        spec = obj["spec"]
        identities.append({
            "type": kind,
            "pod": obj["metadata"]["name"],
            "service_account": spec.get("serviceAccountName"),
            "automount_token": spec.get("automountServiceAccountToken", True),
        })
    return identities


def binding_matches(lab, values):
    role = json.loads(lab.kubectl(
        "-n", NAMESPACE, "get", "role", values["role"], "-o", "json"
    ).stdout)
    binding = json.loads(lab.kubectl(
        "-n", NAMESPACE, "get", "rolebinding", values["binding"], "-o", "json"
    ).stdout)
    expected_rule = [{
        "apiGroups": [""],
        "resources": ["configmaps"],
        "resourceNames": [values["configmap"]],
        "verbs": ["get"],
    }]
    expected_binding = {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": "Role",
        "name": values["role"],
    }
    expected_subject = [{
        "kind": "ServiceAccount",
        "name": values["service_account"],
        "namespace": NAMESPACE,
    }]
    return (
        role.get("rules") == expected_rule
        and binding.get("roleRef") == expected_binding
        and binding.get("subjects") == expected_subject
    )


def create_workloads(lab, shared_account=None):
    for kind, values in WORKLOADS.items():
        pod = pod_for(kind, values, shared_account or values["service_account"])
        lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(pod))
    for values in WORKLOADS.values():
        lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{values['pod']}",
                    "--timeout=95s", timeout=105)


def _run_rbac_checks(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "fixtures.yaml"))
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "shared-binding.yaml"))

    create_workloads(lab, SHARED_ACCOUNT)
    combined = inspect_workloads(lab)
    shared_name = f"system:serviceaccount:{NAMESPACE}:{SHARED_ACCOUNT}"
    shared_access = {name: review(lab, shared_name, name) for name in sorted(CONFIGMAPS)}
    lab.check(
        "red", "The shared workload identity receives all three harmless named reads",
        len(combined) == 3 and all(row["service_account"] == SHARED_ACCOUNT
                                   and row["automount_token"] is False for row in combined)
        and all(decision["allowed"] for decision in shared_access.values()),
        {"workloads": combined, "shared_named_reads": shared_access},
    )
    lab.kubectl("-n", NAMESPACE, "delete", "pods", *(item["pod"] for item in WORKLOADS.values()))
    lab.kubectl("-n", NAMESPACE, "delete", "rolebinding", SHARED_ACCOUNT)
    create_workloads(lab)
    observed_identities = inspect_workloads(lab)
    lab.check(
        "positive",
        "The ordinary synthetic workloads run under three distinct explicit Kubernetes ServiceAccounts",
        len({row["service_account"] for row in observed_identities}) == 3
        and all(row["service_account"] == WORKLOADS[row["type"]]["service_account"]
                and row["automount_token"] is False for row in observed_identities),
        observed_identities,
    )

    usernames = {
        kind: f"system:serviceaccount:{NAMESPACE}:{values['service_account']}"
        for kind, values in WORKLOADS.items()
    }
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "roles-and-bindings.yaml"))
    declarations_match = {
        kind: binding_matches(lab, values)
        for kind, values in WORKLOADS.items()
    }
    lab.check(
        "positive",
        "Each RoleBinding binds one workload ServiceAccount to a Role permitting only get on its exact harmless ConfigMap",
        all(declarations_match.values()),
        declarations_match,
    )

    decisions = {}
    for kind, values in WORKLOADS.items():
        username = usernames[kind]
        decisions[kind] = {
            name: review(lab, username, name)
            for name in sorted(CONFIGMAPS)
        }

    expected = {
        kind: {
            name: (name == values["configmap"])
            for name in CONFIGMAPS
        }
        for kind, values in WORKLOADS.items()
    }
    observed = {
        kind: {
            name: decision["allowed"]
            for name, decision in workload_decisions.items()
        }
        for kind, workload_decisions in decisions.items()
    }
    lab.check(
        "green",
        "API-server authorization preserves each workload's exact named read and withholds the other two named reads",
        observed == expected,
        decisions,
    )

    preserved = {
        kind: decisions[kind][values["configmap"]]
        for kind, values in WORKLOADS.items()
    }
    lab.check(
        "positive",
        "Training, Inference, and Pipeline each retain their own required named read",
        all(decision["allowed"] for decision in preserved.values()),
        preserved,
    )

# Supplemental admission phase. This function is called after the original five
# checks so the existing shared-identity and SAR evidence remains unchanged.
VAP_NAME = "saf-0402-008-workload-serviceaccount"
TYPE_LABEL = "saf-k8s.example/workload-type"
SCOPE_LABEL = "saf-k8s.example/0402-008-vap-scope"
ADMISSION_MESSAGE = "workload-type label must map to its assigned case ServiceAccount"
COMPARATOR_NAMESPACE = "saf-0402-008-vap-outside"


def admission_pod(name, namespace, workload_type, account):
    pod = pod_for(workload_type, {"pod": name}, account)
    pod["metadata"]["namespace"] = namespace
    if workload_type is None:
        del pod["metadata"]["labels"][TYPE_LABEL]
    return pod


def dry_run_create(lab, pod, namespace, timeout=15):
    return lab.kubectl(
        "-n", namespace, "create", "-f", "-", "-o", "json", "--dry-run=server",
        payload=json.dumps(pod), timeout=timeout, allow_failure=True,
    )


def admission_denied(result):
    text = result.stderr + result.stdout
    return result.returncode != 0 and VAP_NAME in text and ADMISSION_MESSAGE in text


def _run_vap_checks_body(lab):
    # Establish the before-activation comparator: the API accepts this wrong
    # mapping when the case-owned policy has not yet been installed.
    baseline = dry_run_create(
        lab, admission_pod("vap-policy-ready-training", NAMESPACE,
                           "training", WORKLOADS["inference"]["service_account"]), NAMESPACE
    )
    lab.check(
        "red", "Before policy activation the API admits the synthetic wrong type/account mapping",
        baseline.returncode == 0,
        {"request": "preactivation-training-to-inference-account", "accepted": baseline.returncode == 0},
    )

    lab.kubectl("label", "namespace", NAMESPACE, f"{SCOPE_LABEL}=enabled", "--overwrite")
    lab.kubectl("apply", "-f", str(HERE / "policy.yaml"))
    scope = json.loads(lab.kubectl("get", "namespace", NAMESPACE, "-o", "json").stdout)
    scope_enabled = scope.get("metadata", {}).get("labels", {}).get(SCOPE_LABEL) == "enabled"
    binding = json.loads(lab.kubectl(
        "get", "validatingadmissionpolicybinding", VAP_NAME, "-o", "json"
    ).stdout)
    policy = json.loads(lab.kubectl(
        "get", "validatingadmissionpolicy", VAP_NAME, "-o", "json"
    ).stdout)
    lab.check(
        "positive", "The case VAP and Deny binding are installed with exact namespace scope",
        scope_enabled
        and binding.get("spec", {}).get("policyName") == VAP_NAME
        and binding.get("spec", {}).get("validationActions") == ["Deny"]
        and binding.get("spec", {}).get("matchResources", {}).get("namespaceSelector", {})
            .get("matchLabels", {}).get(SCOPE_LABEL) == "enabled"
        and policy.get("spec", {}).get("failurePolicy") == "Fail",
        {"scope_label": scope_enabled,
         "binding_policy_matches": binding.get("spec", {}).get("policyName") == VAP_NAME,
         "binding_deny": binding.get("spec", {}).get("validationActions") == ["Deny"],
         "namespace_selector_matches": binding.get("spec", {}).get("matchResources", {})
            .get("namespaceSelector", {}).get("matchLabels", {}).get(SCOPE_LABEL) == "enabled",
         "failure_policy_fail": policy.get("spec", {}).get("failurePolicy") == "Fail"},
    )

    # Wait for the named denial rather than treating admission propagation as
    # an immediate invariant. Bound to 20 seconds, with 10-second API calls.
    ready_probe = admission_pod(
        "vap-policy-ready-training", NAMESPACE, "training",
        WORKLOADS["inference"]["service_account"],
    )
    ready_result = None
    deadline = time.monotonic() + 20
    while True:
        remaining = deadline - time.monotonic()
        if remaining < 8:
            break
        ready_result = dry_run_create(lab, ready_probe, NAMESPACE, timeout=8)
        if admission_denied(ready_result):
            break
        time.sleep(0.5)
    ready = ready_result is not None and admission_denied(ready_result)
    lab.check(
        "green", "The active VAP reaches its exact named denial within the readiness bound",
        ready,
        {"request": "vap-policy-ready-training", "named_denial_observed": ready,
         "within_seconds": 20},
    )

    correct = {}
    for kind, values in WORKLOADS.items():
        result = dry_run_create(
            lab, admission_pod(f"vap-allowed-{kind}", NAMESPACE, kind,
                               values["service_account"]), NAMESPACE
        )
        correct[kind] = result.returncode == 0
        lab.check(
            "positive", f"VAP admits the correct {kind} type-to-ServiceAccount mapping",
            correct[kind], {"type": kind, "accepted": correct[kind]},
        )

    wrong = {}
    kinds = list(WORKLOADS)
    for index, kind in enumerate(kinds):
        other = kinds[(index + 1) % len(kinds)]
        result = dry_run_create(
            lab, admission_pod(f"vap-denied-wrong-{kind}", NAMESPACE, kind,
                               WORKLOADS[other]["service_account"]), NAMESPACE
        )
        wrong[kind] = admission_denied(result)
        lab.check(
            "green", f"VAP denies the wrong ServiceAccount for {kind}", wrong[kind],
            {"type": kind, "wrong_account_type": other, "named_denial": wrong[kind]},
        )

    missing_result = dry_run_create(
        lab, admission_pod("vap-denied-missing-type", NAMESPACE, None,
                           WORKLOADS["training"]["service_account"]), NAMESPACE
    )
    missing_denied = admission_denied(missing_result)
    lab.check(
        "green", "VAP denies a Pod with no workload-type label", missing_denied,
        {"request": "vap-denied-missing-type", "named_denial": missing_denied},
    )
    unknown_result = dry_run_create(
        lab, admission_pod("vap-denied-unknown-type", NAMESPACE, "unknown",
                           WORKLOADS["training"]["service_account"]), NAMESPACE
    )
    unknown_denied = admission_denied(unknown_result)
    lab.check(
        "green", "VAP denies an unknown workload-type label", unknown_denied,
        {"request": "vap-denied-unknown-type", "named_denial": unknown_denied},
    )

    # Submit a real metadata-only update to the owned disposable Pod.
    update_pod = WORKLOADS["training"]["pod"]
    update = lab.kubectl(
        "-n", NAMESPACE, "patch", "pod", update_pod, "--type=merge",
        "-p", json.dumps({"metadata": {"labels": {TYPE_LABEL: "inference"}}}),
        "-o", "json", timeout=15, allow_failure=True,
    )
    update_denied = admission_denied(update)
    lab.check(
        "green", "VAP denies changing a persisted Pod's workload type without matching its ServiceAccount",
        update_denied,
        {"pod": update_pod, "attempted_type": "inference", "named_denial": update_denied},
    )
    persisted = json.loads(lab.kubectl(
        "-n", NAMESPACE, "get", "pod", update_pod, "-o", "json"
    ).stdout)
    persisted_type = persisted.get("metadata", {}).get("labels", {}).get(TYPE_LABEL)
    persisted_account = persisted.get("spec", {}).get("serviceAccountName")
    unchanged = (persisted_type == "training"
                 and persisted_account == WORKLOADS["training"]["service_account"])
    lab.check(
        "positive", "The refused type-changing update leaves the persisted label and ServiceAccount unchanged",
        unchanged,
        {"pod": update_pod, "workload_type_unchanged": persisted_type == "training",
         "service_account_unchanged": persisted_account == WORKLOADS["training"]["service_account"]},
    )

    # A wrong mapping is accepted outside the unique case namespace selector;
    # only server-side dry-run is used, so no Pod is persisted or scheduled.
    comparator_created = False
    try:
        lab.kubectl("create", "namespace", COMPARATOR_NAMESPACE, timeout=15)
        account = {"apiVersion": "v1", "kind": "ServiceAccount",
                   "metadata": {"name": WORKLOADS["inference"]["service_account"],
                                "namespace": COMPARATOR_NAMESPACE},
                   "automountServiceAccountToken": False}
        lab.kubectl("-n", COMPARATOR_NAMESPACE, "create", "-f", "-",
                    payload=json.dumps(account), timeout=15)
        comparator = dry_run_create(
            lab, admission_pod("vap-outside-scope-mismatch", COMPARATOR_NAMESPACE,
                               "training", WORKLOADS["inference"]["service_account"]),
            COMPARATOR_NAMESPACE,
        )
        comparator_created = comparator.returncode == 0
        lab.check(
            "positive", "An otherwise valid synthetic Pod outside the selected namespace is not evaluated by this binding",
            comparator_created,
            {"namespace": COMPARATOR_NAMESPACE, "mismatched_mapping_accepted": comparator_created},
        )
    finally:
        lab.kubectl("delete", "namespace", COMPARATOR_NAMESPACE,
                    "--ignore-not-found=true", timeout=20, allow_failure=True)
        lab.kubectl("delete", "validatingadmissionpolicybinding", VAP_NAME,
                    "--ignore-not-found=true", timeout=15, allow_failure=True)
        lab.kubectl("delete", "validatingadmissionpolicy", VAP_NAME,
                    "--ignore-not-found=true", timeout=15, allow_failure=True)


def run_vap_checks(lab):
    try:
        _run_vap_checks_body(lab)
    finally:
        # Exact-name cleanup also runs if an assertion or API request fails.
        lab.kubectl("delete", "namespace", COMPARATOR_NAMESPACE,
                    "--ignore-not-found=true", timeout=20, allow_failure=True)
        lab.kubectl("delete", "validatingadmissionpolicybinding", VAP_NAME,
                    "--ignore-not-found=true", timeout=15, allow_failure=True)
        lab.kubectl("delete", "validatingadmissionpolicy", VAP_NAME,
                    "--ignore-not-found=true", timeout=15, allow_failure=True)


# The original case.run body above remains intact; invoke additive admission
# checks only after all five published checks have passed.
def run(lab):
    _run_rbac_checks(lab)
    run_vap_checks(lab)
