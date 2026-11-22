"""Observe native label placement on synthetic pipeline resources."""
import json
import time

from fixtures import BUSYBOX_IMAGE


NAMESPACE = "saf-0702-027-pipeline"
CLASSIFICATION = "saf-k8s.example/data-classification"
VALUE = "synthetic-internal"
LABELS = {CLASSIFICATION: VALUE}
SCOPE = (
    "Kubernetes v1.36.1 native API and Job-controller behavior for synthetic Jobs, "
    "their generated Pods, a PVC, a Service, and a ConfigMap. Compares a Job carrying "
    "only object metadata labels with a Job whose Pod template also carries the label; "
    "checks expected-resource coverage and a native label-selector inventory. Does "
    "not test any external orchestrator, automated propagation controller, recurring "
    "audit scheduler, admission enforcement, real data, or organizational taxonomy."
)


def create(lab, resource):
    namespace = resource["metadata"].get("namespace", NAMESPACE)
    return lab.kubectl("-n", namespace, "create", "-f", "-", "-o", "json",
                       payload=json.dumps(resource))


def job(name, *, object_labels=None, template_labels=None):
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": object_labels or {}},
        "spec": {
            "backoffLimit": 0,
            "template": {
                "metadata": {"labels": {"saf-k8s.example/pipeline-stage": name,
                                         **(template_labels or {})}},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "containers": [{"name": "synthetic-step", "image": BUSYBOX_IMAGE,
                                    "command": ["sh", "-c", "printf synthetic-stage-complete"]}],
                },
            },
        },
    }


def generated_pod(lab, job_name):
    parent_uid = get(lab, "job", job_name)["metadata"]["uid"]
    selector = f"batch.kubernetes.io/job-name={job_name}"
    deadline = time.monotonic() + 60
    while True:
        result = lab.kubectl("-n", NAMESPACE, "get", "pods", "-l", selector,
                             "-o", "json")
        pods = json.loads(result.stdout)["items"]
        if pods:
            if len(pods) != 1:
                lab.block(f"Expected one synthetic Pod for Job {job_name}")
            owner = any(r["uid"] == parent_uid and r["kind"] == "Job" and r.get("controller")
                        for r in pods[0]["metadata"].get("ownerReferences", []))
            if not owner:
                lab.block("The matched Pod is not owned by the fixture Job")
            return pods[0]
        if time.monotonic() >= deadline:
            lab.block(f"Job controller did not create a Pod for {job_name}")
        time.sleep(0.5)


def get(lab, kind, name):
    return json.loads(lab.kubectl("-n", NAMESPACE, "get", kind, name, "-o", "json").stdout)


def labels(resource):
    return resource.get("metadata", {}).get("labels", {})


def run(lab):
    lab.kubectl("create", "namespace", NAMESPACE)

    # A parent Job label is not a Pod-template label. The Job controller generates
    # a child Pod from spec.template; Kubernetes does not copy arbitrary parent labels.
    create(lab, job("metadata-only", object_labels=LABELS))
    parent = get(lab, "job", "metadata-only")
    child = generated_pod(lab, "metadata-only")
    lab.check(
        "red",
        "A classification label on Job metadata alone is absent from its generated Pod",
        labels(parent).get(CLASSIFICATION) == VALUE
        and labels(child).get(CLASSIFICATION) is None,
        {"job_label": labels(parent).get(CLASSIFICATION),
         "generated_pod_label": labels(child).get(CLASSIFICATION),
         "expected": {"job": VALUE, "pod": None}},
    )

    # The corrected synthetic pipeline puts the label on both the Job and its Pod
    # template, and on each separately covered Kubernetes resource.
    create(lab, job("template-labeled", object_labels=LABELS,
                    template_labels=LABELS))
    pod = generated_pod(lab, "template-labeled")
    create(lab, {
        "apiVersion": "v1", "kind": "PersistentVolumeClaim",
        "metadata": {"name": "synthetic-input", "namespace": NAMESPACE,
                     "labels": LABELS},
        "spec": {"accessModes": ["ReadWriteOnce"],
                 "resources": {"requests": {"storage": "1Mi"}}},
    })
    create(lab, {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "synthetic-stage", "namespace": NAMESPACE,
                     "labels": LABELS},
        "spec": {"selector": {"saf-k8s.example/pipeline-stage": "template-labeled"},
                 "ports": [{"port": 8080, "targetPort": 8080}]},
    })
    create(lab, {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "synthetic-manifest", "namespace": NAMESPACE,
                     "labels": LABELS},
        "data": {"fixture": "synthetic-only"},
    })

    expected_inventory = [
        ("job", "template-labeled"), ("pod", pod["metadata"]["name"]),
        ("pvc", "synthetic-input"), ("service", "synthetic-stage"),
        ("configmap", "synthetic-manifest"),
    ]
    inventory = [{"kind": kind,
                  "classification": labels(get(lab, kind, name)).get(CLASSIFICATION)}
                 for kind, name in expected_inventory]
    covered = all(item["classification"] == VALUE for item in inventory)
    lab.check(
        "green",
        "The template-labeled pipeline's declared resource inventory retains the classification",
        covered,
        {"expected_resources": len(expected_inventory), "resources": inventory,
         "expected_classification": VALUE},
    )

    selected = lab.kubectl("-n", NAMESPACE, "get", "jobs,pods,pvc,services,configmaps",
                           "-l", f"{CLASSIFICATION}={VALUE}", "-o", "json")
    selected_items = json.loads(selected.stdout)["items"]
    api_kind = {"job": "job", "pod": "pod", "pvc": "persistentvolumeclaim",
                "service": "service", "configmap": "configmap"}
    selected_ids = {(item["kind"].lower(), item["metadata"]["name"]) for item in selected_items}
    expected_ids = {(api_kind[kind], name) for kind, name in expected_inventory}
    complete_selector = selected_ids == expected_ids | {("job", "metadata-only")}
    unclassified_pod_absent = ("pod", child["metadata"]["name"]) not in selected_ids
    lab.check(
        "positive",
        "The label selector includes the labeled parent but misses its unclassified generated Pod",
        complete_selector and unclassified_pod_absent,
        {"label_selected_resources": len(selected_ids), "corrected_inventory_present": complete_selector,
         "unclassified_generated_pod_absent": unclassified_pod_absent},
    )


    for name in ("metadata-only", "template-labeled"):
        lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Complete", f"job/{name}",
                    "--timeout=70s", timeout=80)
        marker = lab.kubectl("-n", NAMESPACE, "logs", f"job/{name}").stdout.strip()
        lab.check("positive", f"The {name} fixture stage completes",
                  marker == "synthetic-stage-complete", {"fixture_stage_completed": marker == "synthetic-stage-complete"})
