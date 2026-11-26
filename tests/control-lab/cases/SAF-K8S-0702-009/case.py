"""Require the AI workload classification schema at Pod and controller admission."""
import json
from pathlib import Path
import time

from fixtures import container, pod

HERE = Path(__file__).parent
NAMESPACE = "saf-0702-009-ai"
DENIAL = "all three AI workload classification labels must be present and use governed values"
LABELS = {
    "ai.kais.io/workload-type": "inference",
    "ai.kais.io/data-sensitivity": "internal",
    "ai.kais.io/model-tier": "staging",
}
APP_LABEL = "saf-k8s.example/app"
APP_NAME = "saf-0702-009-probe"
SCOPE = (
    "Native Kubernetes ValidatingAdmissionPolicy CREATE and UPDATE enforcement of the "
    "SAF-K8S-0702-005 AI classification labels on Pods and Job, Deployment, and StatefulSet "
    "templates in one synthetic namespace. Includes absent and ungoverned values, exact "
    "denials, selected and unselected namespace probes for the named kinds, valid admitted "
    "CREATEs, namespace separation and an admitted Deployment rollout. Namespace enrollment "
    "governance, exceptions, CronJobs, DaemonSets, existing-object migration, and production "
    "policy rollout are separate."
)


def class_labels(variant="valid"):
    labels = dict(LABELS)
    if variant == "missing":
        del labels["ai.kais.io/model-tier"]
    elif variant == "wrong":
        labels["ai.kais.io/workload-type"] = "unapproved"
    return labels


def pod_resource(name, variant="valid"):
    resource = pod(name, [container("probe")], automountServiceAccountToken=False)
    resource["metadata"].update(namespace=NAMESPACE, labels=class_labels(variant))
    return resource


def template_resource(kind, name, variant="valid"):
    labels = {APP_LABEL: APP_NAME, **class_labels(variant)}
    restart_policy = "Never" if kind == "Job" else "Always"
    template = {
        "metadata": {"labels": labels},
        "spec": {"restartPolicy": restart_policy, "containers": [container("probe")],
                 "automountServiceAccountToken": False},
    }
    base = {"metadata": {"name": name, "namespace": NAMESPACE}}
    if kind == "Deployment":
        base.update(apiVersion="apps/v1", kind=kind, spec={
            "replicas": 0, "selector": {"matchLabels": {APP_LABEL: APP_NAME}},
            "template": template,
        })
    elif kind == "StatefulSet":
        base.update(apiVersion="apps/v1", kind=kind, spec={
            "serviceName": "saf-0702-009-headless", "replicas": 0,
            "selector": {"matchLabels": {APP_LABEL: APP_NAME}}, "template": template,
        })
    elif kind == "Job":
        base.update(apiVersion="batch/v1", kind=kind, spec={
            "backoffLimit": 0, "suspend": True, "template": template,
        })
    else:
        raise ValueError(f"unsupported workload kind: {kind}")
    return base


def server_create(lab, resource, namespace=NAMESPACE):
    return lab.kubectl(
        "-n", namespace, "create", "-f", "-", "--dry-run=server", "-o", "json",
        payload=json.dumps(resource), allow_failure=True,
    )


def server_patch(lab, kind, name, path, value):
    patch = {}
    cursor = patch
    for key in path[:-1]:
        cursor[key] = {}
        cursor = cursor[key]
    cursor[path[-1]] = value
    return lab.kubectl(
        "-n", NAMESPACE, "patch", kind, name, "--type=merge", "-p", json.dumps(patch),
        "--dry-run=server", "-o", "json", allow_failure=True,
    )


def denied(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and DENIAL in result.stderr)


def run(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf-k8s.example/classification-enforcement=required")

    create_probes = [("Pod", variant, pod_resource(f"pod-{variant}", variant))
                     for variant in ("missing", "wrong")]
    create_probes += [(kind, variant, template_resource(kind, f"{kind.lower()}-{variant}", variant))
                      for kind in ("Deployment", "StatefulSet", "Job")
                      for variant in ("missing", "wrong")]
    red_results = [(kind, variant, server_create(lab, resource))
                   for kind, variant, resource in create_probes]
    lab.check(
        "red", "Inactive admission permits absent or wrong labels on all tested CREATE shapes",
        all(result.returncode == 0 for _, _, result in red_results),
        [{"kind": kind, "variant": variant,
          "accepted": result.returncode == 0, "detail": result.stderr.strip()}
         for kind, variant, result in red_results],
    )

    # Persist only compliant, zero-replica controller templates for UPDATE dry-runs.
    for resource in (pod_resource("update-pod"),
                     template_resource("Deployment", "update-deployment"),
                     template_resource("StatefulSet", "update-statefulset"),
                     template_resource("Job", "update-job")):
        result = lab.kubectl("-n", NAMESPACE, "create", "-f", "-",
                             payload=json.dumps(resource), allow_failure=True)
        lab.check("red", f"Compliant {resource['kind']} baseline is created before policy",
                  result.returncode == 0, result.stderr.strip() or "created")

    update_probes = [
        ("Pod", "update-pod", ["metadata", "labels"], class_labels("wrong")),
        ("Deployment", "update-deployment", ["spec", "template", "metadata", "labels"],
         {APP_LABEL: APP_NAME, **class_labels("wrong")}),
        ("Job", "update-job", ["spec", "template", "metadata", "labels"],
         {APP_LABEL: APP_NAME, **class_labels("wrong")}),
        ("StatefulSet", "update-statefulset", ["spec", "template", "metadata", "labels"],
         {APP_LABEL: APP_NAME, **class_labels("wrong")}),
    ]
    red_updates = [(kind, server_patch(lab, kind.lower(), name, path, value))
                   for kind, name, path, value in update_probes]
    lab.check("red", "Inactive admission permits wrong labels on tested UPDATE shapes",
              all(result.returncode == 0 for _, result in red_updates),
              [{"kind": kind, "accepted": result.returncode == 0,
                "detail": result.stderr.strip()} for kind, result in red_updates])

    lab.apply(HERE / "admission-policy.yaml")
    deadline = time.monotonic() + 15
    while True:
        green_results = [(kind, variant, server_create(lab, resource))
                         for kind, variant, resource in create_probes]
        green_updates = [(kind, server_patch(lab, kind.lower(), name, path, value))
                         for kind, name, path, value in update_probes]
        if (all(denied(result) for _, _, result in green_results)
                and all(denied(result) for _, result in green_updates)
                or time.monotonic() >= deadline):
            break
        time.sleep(0.5)

    lab.check(
        "green", "CREATE rejects missing and wrong labels with the exact policy denial",
        all(denied(result) for _, _, result in green_results),
        [{"kind": kind, "variant": variant, "denied_by_policy": denied(result),
          "detail": result.stderr.strip()}
         for kind, variant, result in green_results],
    )
    lab.check(
        "green", "UPDATE rejects wrong labels with the exact policy denial",
        all(denied(result) for _, result in green_updates),
        [{"kind": kind, "denied_by_policy": denied(result), "detail": result.stderr.strip()}
         for kind, result in green_updates],
    )

    positive_pod = server_create(lab, pod_resource("permitted-pod"))
    positive_deployment = server_create(
        lab, template_resource("Deployment", "permitted-deployment"))
    lab.check(
        "positive", "Permitted governed class succeeds for Pod and Deployment template dry-runs",
        positive_pod.returncode == 0 and positive_deployment.returncode == 0,
        {"pod": "admitted" if positive_pod.returncode == 0 else positive_pod.stderr.strip(),
         "deployment": "admitted" if positive_deployment.returncode == 0
         else positive_deployment.stderr.strip()},
    )

    positive_controller_templates = [
        (kind, server_create(lab, template_resource(kind, f"permitted-{kind.lower()}")))
        for kind in ("Job", "StatefulSet")
    ]
    lab.check(
        "positive", "Governed Job and StatefulSet templates pass active-policy CREATE dry-runs",
        all(result.returncode == 0 for _, result in positive_controller_templates),
        [{"kind": kind, "accepted": result.returncode == 0,
          "detail": result.stderr.strip()}
         for kind, result in positive_controller_templates],
    )


    outside_scope = pod_resource("outside-scope", "missing")
    outside_scope["metadata"]["namespace"] = "saf-test"
    excluded = server_create(lab, outside_scope, "saf-test")
    lab.check("positive", "An unlabeled fixture in the unselected namespace remains admissible",
              excluded.returncode == 0, {"outside_scope_admitted": excluded.returncode == 0})

    unselected_controller_probes = []
    for kind in ("Job", "Deployment", "StatefulSet"):
        resource = template_resource(kind, f"outside-{kind.lower()}", "missing")
        resource["metadata"]["namespace"] = "saf-test"
        result = server_create(lab, resource, "saf-test")
        unselected_controller_probes.append((kind, result))
    lab.check(
        "positive", "Unlabeled controller templates remain admissible in the unselected namespace",
        all(result.returncode == 0 for _, result in unselected_controller_probes),
        [{"kind": kind, "outside_scope_admitted": result.returncode == 0,
          "detail": result.stderr.strip()}
         for kind, result in unselected_controller_probes],
    )

    live = template_resource("Deployment", "permitted-live")
    live["spec"]["replicas"] = 1
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(live))
    rolled_out = lab.kubectl("-n", NAMESPACE, "rollout", "status", "deployment/permitted-live",
                             "--timeout=80s", timeout=90).returncode == 0
    objects = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pods", "-l", f"{APP_LABEL}={APP_NAME}",
                                     "-o", "json").stdout)["items"]
    labels = objects[0]["metadata"].get("labels", {}) if len(objects) == 1 else {}
    labels_match = all(labels.get(name) == value for name, value in LABELS.items())
    lab.check("positive", "The admitted Deployment produces a Ready Pod with governed labels",
              rolled_out and labels_match, {"deployment_ready": rolled_out, "labels_match": labels_match})
