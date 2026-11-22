"""Validate the catalog's minimum AI workload classification labels."""
import json
from pathlib import Path
import time

from fixtures import container, pod

HERE = Path(__file__).parent
NAMESPACE = "saf-0702-005-ai"
DENIAL = "all three AI workload classification labels must be present and use governed values"
LABELS = {
    "ai.kais.io/workload-type": "inference",
    "ai.kais.io/data-sensitivity": "internal",
    "ai.kais.io/model-tier": "staging",
}
VALUES = {
    "ai.kais.io/workload-type": ["training", "inference", "preprocessing", "evaluation", "notebook"],
    "ai.kais.io/data-sensitivity": ["public", "internal", "confidential", "restricted"],
    "ai.kais.io/model-tier": ["experimental", "staging", "production"],
}
SCOPE = (
    "Kubernetes v1.36.1 ValidatingAdmissionPolicy CREATE enforcement on synthetic Pods "
    "for presence and enumerated values of the three minimum SAF-K8S-0702-005 labels; "
    "native label-selector inventory of benign classified Pods; and an actual ResourceQuota "
    "API request verifying supported scopeSelector names. "
    "Does not test annotations, controller templates, namespace enrollment, scheduling, "
    "NetworkPolicy traffic, audit backend filtering, or organizational governance."
)


def pod_resource(name, labels):
    resource = pod(name, [container("probe")], automountServiceAccountToken=False)
    resource["metadata"].update(namespace=NAMESPACE, labels=labels)
    return resource


def server_create(lab, resource):
    return lab.kubectl(
        "-n", NAMESPACE, "create", "-f", "-", "--dry-run=server", "-o", "json",
        payload=json.dumps(resource), allow_failure=True,
    )


def denied(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and DENIAL in result.stderr)


def run(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf-k8s.example/classification-enforcement=required")

    probes = []
    for key in LABELS:
        absent = dict(LABELS)
        del absent[key]
        probes.append((key, "absent", pod_resource(f"red-absent-{len(probes)}", absent)))
        wrong = dict(LABELS)
        wrong[key] = "unapproved"
        probes.append((key, "wrong", pod_resource(f"red-wrong-{len(probes)}", wrong)))

    red = [(key, variant, server_create(lab, resource))
           for key, variant, resource in probes]
    lab.check(
        "red", "Without the policy the API accepts each absent and wrong category probe",
        all(result.returncode == 0 for _, _, result in red),
        [{"category": key, "variant": variant, "accepted": result.returncode == 0,
          "detail": result.stderr.strip()} for key, variant, result in red],
    )

    lab.apply(HERE / "classification-policy.yaml")
    deadline = time.monotonic() + 20
    while True:
        green = [(key, variant, server_create(lab, resource))
                 for key, variant, resource in probes]
        if all(denied(result) for _, _, result in green) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check(
        "green", "The policy denies each absent and wrong category with its exact message",
        all(denied(result) for _, _, result in green),
        [{"category": key, "variant": variant, "denied_by_policy": denied(result),
          "detail": result.stderr.strip()} for key, variant, result in green],
    )

    admitted_values = {}
    for category, values in VALUES.items():
        admitted_values[category] = []
        for value in values:
            result = server_create(lab, pod_resource("permitted-value", {**LABELS, category: value}))
            if result.returncode == 0:
                admitted_values[category].append(value)
    lab.check("positive", "Every enumerated value remains admissible in its own category",
              admitted_values == VALUES, admitted_values)

    valid = pod_resource("permitted-inference", LABELS)
    valid["metadata"]["labels"]["saf-k8s.example/case"] = "0702-005"
    admitted = lab.kubectl("-n", NAMESPACE, "create", "-f", "-", "-o", "json",
                           payload=json.dumps(valid), allow_failure=True)
    lab.check("positive", "A permitted governed inference Pod is admitted",
              admitted.returncode == 0,
              admitted.stderr.strip() or "created")

    other_labels = dict(LABELS)
    other_labels["ai.kais.io/workload-type"] = "training"
    other = pod_resource("permitted-training", other_labels)
    other["metadata"]["labels"]["saf-k8s.example/case"] = "0702-005"
    other_result = lab.kubectl("-n", NAMESPACE, "create", "-f", "-", "-o", "json",
                               payload=json.dumps(other), allow_failure=True)
    lab.check("positive", "A second benign governed class is admitted",
              other_result.returncode == 0,
              other_result.stderr.strip() or "created")

    selected = lab.kubectl(
        "-n", NAMESPACE, "get", "pods", "-l", "ai.kais.io/workload-type=inference",
        "-o", "json",
    )
    selected_names = sorted(item["metadata"]["name"]
                            for item in json.loads(selected.stdout)["items"])
    lab.check(
        "positive", "A native label selector supports benign classification inventory",
        selected_names == ["permitted-inference"],
        {"selector": "ai.kais.io/workload-type=inference", "selected": selected_names},
    )

    custom_quota = {
        "apiVersion": "v1", "kind": "ResourceQuota",
        "metadata": {"name": "classification-quota", "namespace": NAMESPACE},
        "spec": {"hard": {"pods": "3"}, "scopeSelector": {"matchExpressions": [{
            "scopeName": "ai.kais.io/workload-type", "operator": "In",
            "values": ["inference"],
        }]}},
    }
    quota_result = lab.kubectl("-n", NAMESPACE, "create", "-f", "-",
                               payload=json.dumps(custom_quota), allow_failure=True)
    quota_error = quota_result.stderr.strip()
    lab.check(
        "green", "The API rejects a custom classification label as a ResourceQuota scope",
        quota_result.returncode != 0 and "ai.kais.io/workload-type" in quota_error
        and "unsupported scope" in quota_error.lower(),
        {"rejected": quota_result.returncode != 0, "detail": quota_error},
    )

    supported_quota = {
        "apiVersion": "v1", "kind": "ResourceQuota",
        "metadata": {"name": "priority-class-quota", "namespace": NAMESPACE},
        "spec": {"hard": {"pods": "3"}, "scopeSelector": {"matchExpressions": [{
            "scopeName": "PriorityClass", "operator": "In", "values": ["saf-lab-low"],
        }]}},
    }
    supported_result = lab.kubectl("-n", NAMESPACE, "create", "-f", "-", "-o", "json",
                                   payload=json.dumps(supported_quota), allow_failure=True)
    lab.check("positive", "The same API accepts a built-in PriorityClass quota scope",
              supported_result.returncode == 0,
              supported_result.stderr.strip() or "created")
