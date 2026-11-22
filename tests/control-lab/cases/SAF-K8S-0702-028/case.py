"""Check classification admission on inert synthetic pipeline templates."""
import json
from pathlib import Path
import time


HERE = Path(__file__).parent
NAMESPACE = "saf-0702-028-pipeline"
POLICY = "saf-k8s-0702-028-pipeline-classification"
BINDING = POLICY
CLASSIFICATION = "saf-k8s.example/data-classification"
REQUIRED = "saf-k8s.example/required-classification"
EXPECTED = "confidential"
DENIAL = "pipeline template classification must be present and match the namespace requirement"
APP_LABEL = "saf-k8s.example/case"
APP_VALUE = "saf-k8s-0702-028"
SCOPE = (
    "Kubernetes v1.36.1 native ValidatingAdmissionPolicy checks for synthetic Deployment "
    "and suspended Job CREATE and UPDATE in one case-owned namespace. "
    "The namespace requires the synthetic confidential classification. The case verifies "
    "compliant admission and exact policy denials for missing and mismatched values, "
    "including template UPDATE dry-runs. It does not test workflow engines, "
    "other resource kinds, namespace enrollment governance, existing cluster workloads, "
    "or production classification processes."
)


def labels(classification=EXPECTED):
    result = {APP_LABEL: APP_VALUE}
    if classification is not None:
        result[CLASSIFICATION] = classification
    return result


def workload(kind, name, classification=EXPECTED):
    template = {
        "metadata": {"labels": labels(classification)},
        "spec": {
            "restartPolicy": "Never" if kind == "Job" else "Always",
            "containers": [{"name": "placeholder", "image": "registry.k8s.io/pause:3.10"}],
            "automountServiceAccountToken": False,
        },
    }
    resource = {"metadata": {"name": name, "namespace": NAMESPACE}}
    if kind == "Deployment":
        resource.update(apiVersion="apps/v1", kind=kind, spec={
            "replicas": 0,
            "selector": {"matchLabels": {APP_LABEL: APP_VALUE}},
            "template": template,
        })
    elif kind == "Job":
        resource.update(apiVersion="batch/v1", kind=kind, spec={
            "suspend": True,
            "backoffLimit": 0,
            "template": template,
        })
    else:
        raise ValueError(f"unsupported pipeline fixture kind: {kind}")
    return resource


def server_create(lab, resource):
    return lab.kubectl(
        "create", "-f", "-", "-n", NAMESPACE, "--dry-run=server", "-o", "json",
        payload=json.dumps(resource), allow_failure=True,
    )


def server_label_update(lab, kind, classification):
    name = f"update-{kind.lower()}"
    patch = {"spec": {"template": {"metadata": {"labels": {CLASSIFICATION: classification}}}}}
    return lab.kubectl(
        "-n", NAMESPACE, "patch", kind.lower(), name, "--type=merge",
        "-p", json.dumps(patch), "--dry-run=server", "-o", "json",
        allow_failure=True,
    )


def admitted(result):
    return result.returncode == 0


def denied_by_policy(result):
    detail = result.stderr
    return (
        result.returncode != 0
        and "(Forbidden)" in detail
        and f"ValidatingAdmissionPolicy '{POLICY}'" in detail
        and f"binding '{BINDING}'" in detail
        and DENIAL in detail
    )


def summary(kind, variant, result):
    return {
        "kind": kind,
        "variant": variant,
        "admitted": admitted(result),
        "denied_by_expected_policy": denied_by_policy(result),
    }


def run(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl(
        "label", "namespace", NAMESPACE,
        "saf-k8s.example/classification-enforcement=required",
        f"{REQUIRED}={EXPECTED}",
    )

    create_probes = [
        (kind, variant, workload(kind, f"{kind.lower()}-{variant}", classification))
        for kind in ("Deployment", "Job")
        for variant, classification in (("missing", None), ("mismatch", "public"))
    ]
    red = [(kind, variant, server_create(lab, resource))
           for kind, variant, resource in create_probes]
    lab.check(
        "red", "Without the case policy, missing and mismatched synthetic classifications reach the API",
        all(admitted(result) for _, _, result in red),
        [summary(kind, variant, result) for kind, variant, result in red],
    )

    # Persist inert, compliant fixtures before policy activation so UPDATE
    # dry-runs reach the same admission rule.
    for resource in (
        workload("Deployment", "update-deployment"),
        workload("Job", "update-job"),
    ):
        result = lab.kubectl(
            "create", "-f", "-", "-n", NAMESPACE,
            payload=json.dumps(resource), allow_failure=True,
        )
        lab.check(
            "red", f"Compliant {resource['kind']} update baseline is created before policy",
            admitted(result), result.stderr.strip() or "created",
        )

    variants = [(kind, variant, classification)
                for kind in ("Deployment", "Job")
                for variant, classification in (("missing", None), ("mismatch", "public"))]
    red_updates = [(kind, variant, server_label_update(lab, kind, classification))
                   for kind, variant, classification in variants]
    lab.check(
        "red", "Both kinds accept updates that remove or mismatch labels before policy activation",
        all(admitted(result) for _, _, result in red_updates),
        [summary(kind, variant, result) for kind, variant, result in red_updates],
    )

    lab.apply(HERE / "admission-policy.yaml")
    first_kind, first_variant, first_resource = create_probes[0]
    ready_probe = server_create(lab, first_resource)
    deadline = time.monotonic() + 20
    while not denied_by_policy(ready_probe) and time.monotonic() < deadline:
        time.sleep(0.5)
        ready_probe = server_create(lab, first_resource)
    green = [(kind, variant, server_create(lab, resource))
             for kind, variant, resource in create_probes]
    green[0] = (first_kind, first_variant, ready_probe)
    lab.check(
        "green", "CREATE denies missing and mismatched metadata for both pipeline fixture kinds for the policy reason",
        all(denied_by_policy(result) for _, _, result in green),
        [summary(kind, variant, result) for kind, variant, result in green],
    )

    green_updates = [(kind, variant, server_label_update(lab, kind, classification))
                     for kind, variant, classification in variants]
    lab.check(
        "green", "Both kinds reject updates that remove or mismatch labels under the policy",
        all(denied_by_policy(result) for _, _, result in green_updates),
        [summary(kind, variant, result) for kind, variant, result in green_updates],
    )

    kinds = ("Deployment", "Job")
    creates = {kind: admitted(server_create(lab, workload(kind, f"{kind.lower()}-valid")))
               for kind in kinds}
    updates = {kind: admitted(server_label_update(lab, kind, EXPECTED)) for kind in kinds}
    lab.check(
        "positive", "Both kinds admit matching confidential metadata on CREATE and UPDATE",
        all((*creates.values(), *updates.values())), {"creates": creates, "updates": updates},
    )
