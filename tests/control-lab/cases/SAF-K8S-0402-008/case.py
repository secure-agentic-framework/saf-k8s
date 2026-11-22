"""Review distinct AI-workload ServiceAccounts and named-read RBAC via SAR."""
import json
from pathlib import Path

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
    "credentials. External cloud IAM, federated identities, admission mapping "
    "enforcement, Kubeflow, KServe, training operators, production resources, "
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


def run(lab):
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
