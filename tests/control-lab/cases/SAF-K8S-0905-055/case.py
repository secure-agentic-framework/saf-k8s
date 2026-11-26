"""Verify declared model source admission against a current ConfigMap allowlist."""
from copy import deepcopy
import json
import time

NS = "saf-test"
OUTSIDE = "saf-source-outside"
PARAM = "model-source-allowlist"
APPROVED_URL = "https://models.example.test/approved/model-v1"
APPROVED_OCI = "registry.example.test/approved/model:v1"
APPROVED_MODEL_CARRIER_IMAGE = "registry.example.test/approved/model-runtime:v1"
OTHER_MODEL_CARRIER_IMAGE = "registry.unapproved.test/fixture/model-runtime:v9"
UNRELATED_HELPER_IMAGE = "registry.unrelated.test/fixtures/worker:v1"
OTHER_URL = "https://other.example.test/unapproved/model-v1"
OTHER_OCI = "registry.other.test/unapproved/model:v1"
NEXT_URL = "https://models.example.test/approved/model-v2"
URL_VAR = "MODEL_SOURCE_URL"
OCI_VAR = "MODEL_SOURCE_OCI"
DENIAL = "declared model source is outside the approved allowlist"
SCOPE = (
    "Native Kubernetes v1.36.1 admission checks exact HTTPS and OCI values in declared "
    "environment fields on Pods, Deployments, ReplicaSets, ReplicationControllers, StatefulSets, DaemonSets, Jobs and CronJobs "
    "in a protected namespace, including normal and init containers. Requests use server "
    "dry-run and a real zero-replica Deployment. A separate VAP checks the image of a "
    "container explicitly named model-carrier on Pods and Deployments against its own "
    "key in the same ConfigMap; unrelated container images are not interpreted as model "
    "carriers. No image is pulled. The test covers an admissible update, allowlist rotation "
    "and a missing parameter. Other model-source fields, additional image-carrier object "
    "kinds, actual image pulls and production governance remain open."
)


def _workload(kind, *, ns=NS, source=APPROVED_URL, oci=APPROVED_OCI, name=None):
    api = ("v1" if kind in ("Pod", "ReplicationController")
           else "batch/v1" if kind in ("Job", "CronJob") else "apps/v1")
    name = name or f"fixture-{kind.lower()}"
    workload = {"apiVersion": api, "kind": kind, "metadata": {"name": name, "namespace": ns}}
    spec = {"automountServiceAccountToken": False,
            "containers": [{"name": "worker", "image": "registry.invalid/saf-fixture/inert:1",
                            "env": [{"name": URL_VAR, "value": source},
                                    {"name": OCI_VAR, "value": oci}]}]}
    if kind in ("Pod", "Job", "CronJob"):
        spec["restartPolicy"] = "Never"
    labels = {"app": name}
    template = {"metadata": {"labels": labels}, "spec": spec}
    if kind == "Pod":
        workload["spec"] = spec
    elif kind == "CronJob":
        workload["spec"] = {"schedule": "0 0 1 * *", "suspend": True,
                            "jobTemplate": {"spec": {"template": template}}}
    elif kind == "Job":
        workload["spec"] = {"template": template}
    else:
        selector = labels if kind == "ReplicationController" else {"matchLabels": labels}
        workload["spec"] = {"selector": selector, "template": template}
        if kind != "DaemonSet":
            workload["spec"]["replicas"] = 0
        if kind == "StatefulSet":
            workload["spec"]["serviceName"] = "fixture-model"
    return workload


def _request(lab, obj, *, operation="create", dry=True):
    args = ["-n", obj["metadata"]["namespace"], operation, "-f", "-", "-o", "json"]
    if dry:
        args.append("--dry-run=server")
    return lab.kubectl(*args, payload=json.dumps(obj), allow_failure=True)


def _update(lab):
    patch = [{"op": "replace", "path": "/spec/template/spec/containers/0/env/0/value", "value": OTHER_URL}]
    return lab.kubectl("patch", "deployment/persisted-deployment", "--type=json",
                       "-p", json.dumps(patch), "--dry-run=server", "-o", "json", allow_failure=True)


def _map(lab, urls):
    obj = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": PARAM, "namespace": NS},
           "data": {"https": ",".join(urls), "oci": APPROVED_OCI,
                    "model_carrier_images": APPROVED_MODEL_CARRIER_IMAGE}}
    lab.kubectl("apply", "-f", "-", payload=json.dumps(obj))


def _install(lab, name, spec, resources):
    expression = (
        "params != null && has(params.data) && has(params.data.https) && has(params.data.oci) && "
        f"({spec}.containers + (has({spec}.initContainers) ? {spec}.initContainers : [])).all(c, "
        "(!has(c.env) || c.env.all(e, "
        f"(e.name != '{URL_VAR}' || (has(e.value) && e.value != '' && e.value in params.data.https.split(','))) && "
        f"(e.name != '{OCI_VAR}' || (has(e.value) && e.value != '' && e.value in params.data.oci.split(',')))"
        ")))"
    )
    lab.create({
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": name},
        "spec": {"failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
                 "matchConstraints": {"resourceRules": [
                     {"apiGroups": [group], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"],
                      "resources": names, "scope": "Namespaced"} for group, names in resources]},
                 "validations": [{"expression": expression, "message": DENIAL, "reason": "Forbidden"}]},
    })
    lab.create({
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": name},
        "spec": {"policyName": name, "validationActions": ["Deny"],
                 "paramRef": {"name": PARAM, "namespace": NS, "parameterNotFoundAction": "Deny"},
                 "matchResources": {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": NS}}}},
    })


def _policy_name(kind):
    return {"Pod": "model-source-pod", "CronJob": "model-source-cronjob"}.get(kind, "model-source-template")


def _check_denial(lab, description, obj, *, update=False, param_missing=False, converge=False):
    deadline = time.monotonic() + 15
    while True:
        result = _update(lab) if update else _request(lab, obj)
        error = result.stderr
        expected = "param" in error.lower() if param_missing else DENIAL in error
        named = "ValidatingAdmissionPolicy '" + _policy_name(obj["kind"]) + "'" in error
        if (result.returncode and named and expected) or not converge or time.monotonic() >= deadline:
            break
        time.sleep(0.3)
    lab.check("green", description, result.returncode != 0 and named and expected,
              {"api_rejection": result.returncode != 0, "expected_policy_named": named,
               "expected_parameter_error" if param_missing else "expected_denial_message": expected})


def _check_create(lab, description, obj, *, phase="positive"):
    result = _request(lab, obj)
    lab.check(phase, description, result.returncode == 0,
              {"admitted": result.returncode == 0, "kind": obj["kind"], "namespace": obj["metadata"]["namespace"]})



def _model_carrier_workload(kind, *, image=None, carrier=True):
    name = f"model-carrier-{kind.lower()}"
    containers = []
    if carrier:
        containers.append({"name": "model-carrier", "image": image or APPROVED_MODEL_CARRIER_IMAGE})
    containers.append({"name": "ordinary-helper", "image": UNRELATED_HELPER_IMAGE})
    pod_spec = {"automountServiceAccountToken": False, "containers": containers}
    if kind == "Pod":
        return {"apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": name, "namespace": NS},
                "spec": {**pod_spec, "restartPolicy": "Never"}}
    labels = {"app": name}
    return {"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": name, "namespace": NS},
            "spec": {"replicas": 0, "selector": {"matchLabels": labels},
                     "template": {"metadata": {"labels": labels}, "spec": pod_spec}}}


def _install_model_carrier_image_policy(lab):
    def field(spec):
        return (
            "params != null && has(params.data) && has(params.data.model_carrier_images) && "
            f"{spec}.containers.all(c, c.name != 'model-carrier' || "
            "c.image in params.data.model_carrier_images.split(',')) && "
            f"(!has({spec}.initContainers) || {spec}.initContainers.all(c, "
            "c.name != 'model-carrier' || c.image in params.data.model_carrier_images.split(',')))"
        )

    expression = (
        "object.kind == 'Pod' ? (" + field("object.spec") + ") : (" +
        field("object.spec.template.spec") + ")"
    )
    lab.create({
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": "model-carrier-image-source"},
        "spec": {"failurePolicy": "Fail",
                 "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
                 "matchConstraints": {"resourceRules": [
                     {"apiGroups": [""], "apiVersions": ["v1"],
                      "operations": ["CREATE", "UPDATE"], "resources": ["pods"],
                      "scope": "Namespaced"},
                     {"apiGroups": ["apps"], "apiVersions": ["v1"],
                      "operations": ["CREATE", "UPDATE"], "resources": ["deployments"],
                      "scope": "Namespaced"}]},
                 "validations": [{"expression": expression,
                                  "message": "model carrier image is outside the approved source allowlist",
                                  "reason": "Forbidden"}]}
    })
    lab.create({
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": "model-carrier-image-source"},
        "spec": {"policyName": "model-carrier-image-source", "validationActions": ["Deny"],
                 "paramRef": {"name": PARAM, "namespace": NS,
                              "parameterNotFoundAction": "Deny"},
                 "matchResources": {"namespaceSelector": {
                     "matchLabels": {"kubernetes.io/metadata.name": NS}}}}
    })


def _exercise_model_carrier_image_policy(lab):
    bad = {kind: _model_carrier_workload(kind, image=OTHER_MODEL_CARRIER_IMAGE)
           for kind in ("Pod", "Deployment")}
    before = {kind: _request(lab, obj).returncode == 0 for kind, obj in bad.items()}
    lab.check("red", "Unapproved model-carrier image references reach Pod and Deployment admission before their image policy",
              all(before.values()), {kind.lower() + "_admitted_before_policy": value
                                     for kind, value in before.items()})

    _install_model_carrier_image_policy(lab)
    denied = {kind: False for kind in bad}
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and not all(denied.values()):
        for kind, obj in bad.items():
            result = _request(lab, obj)
            denied[kind] = (result.returncode != 0
                            and "ValidatingAdmissionPolicy 'model-carrier-image-source'" in result.stderr
                            and "model carrier image is outside the approved source allowlist" in result.stderr)
        if not all(denied.values()):
            time.sleep(0.4)
    approved = {kind: _request(lab, _model_carrier_workload(kind)).returncode == 0
                for kind in ("Pod", "Deployment")}
    unrelated = {kind: _request(lab, _model_carrier_workload(kind, carrier=False)).returncode == 0
                 for kind in ("Pod", "Deployment")}
    observed = {
        "unapproved_model_carrier_denied_for_pod_and_deployment": all(denied.values()),
        "approved_model_carrier_allowed_for_pod_and_deployment": all(approved.values()),
        "unrelated_helper_image_outside_allowlist_allowed": all(unrelated.values()),
    }
    lab.check("green", "Model-carrier images use the exact allowlist while unrelated workload images remain admissible",
              all(observed.values()), observed)


def run(lab):
    lab.kubectl("create", "namespace", OUTSIDE)
    _map(lab, [APPROVED_URL])
    kinds = ("Pod", "Deployment", "ReplicaSet", "ReplicationController",
             "StatefulSet", "DaemonSet", "Job", "CronJob")
    denied = {kind: _workload(kind, source=OTHER_URL) for kind in kinds}
    bad_oci = _workload("Pod", oci=OTHER_OCI)
    indirect = _workload("Pod")
    indirect["spec"]["containers"][0]["env"][0] = {"name": URL_VAR, "valueFrom": {
        "configMapKeyRef": {"name": "unreviewed-value", "key": "source"}}}
    bad_init = _workload("Pod")
    bad_init["spec"]["initContainers"] = [deepcopy(denied["Pod"]["spec"]["containers"][0])]
    bad_init["spec"]["initContainers"][0]["name"] = "initializer"
    for kind in kinds:
        _check_create(lab, f"The exact alternate-source {kind} reaches the API before enrollment", denied[kind], phase="red")
    for name, obj in (("OCI reference", bad_oci), ("indirect value", indirect), ("init container", bad_init)):
        _check_create(lab, f"The alternate {name} is accepted before enrollment", obj, phase="red")

    actual = _request(lab, _workload("Deployment", name="persisted-deployment"), dry=False)
    if actual.returncode:
        lab.block("Unable to create the zero-replica workload before testing a mutable field")
    uncontrolled_update = _update(lab)
    lab.check("red", "The same valid stored Deployment update is accepted before enrollment",
              uncontrolled_update.returncode == 0, {"update_admitted": uncontrolled_update.returncode == 0})

    _install(lab, "model-source-pod", "object.spec", [("", ["pods"])])
    _install(lab, "model-source-template", "object.spec.template.spec",
             [("apps", ["deployments", "replicasets", "statefulsets", "daemonsets"]),
         ("", ["replicationcontrollers"]), ("batch", ["jobs"])])
    _install(lab, "model-source-cronjob", "object.spec.jobTemplate.spec.template.spec", [("batch", ["cronjobs"])])
    for kind in kinds:
        _check_denial(lab, f"The enrolled API rejects the alternate-source {kind} for the expected policy",
                       denied[kind], converge=True)
        _check_create(lab, f"The enrolled API still accepts approved source values on {kind}", _workload(kind))
    _check_denial(lab, "A declared OCI reference outside the allowlist is denied", bad_oci)
    _check_denial(lab, "A declared source parameter supplied by valueFrom is denied", indirect)
    _check_denial(lab, "A declared source in an init container is checked", bad_init)
    _check_denial(lab, "The API blocks the same update to the persisted Deployment", _workload("Deployment"), update=True)
    _check_create(lab, "The alternate source is still admissible outside the enrolled namespace",
                  _workload("Pod", ns=OUTSIDE, source=OTHER_URL, oci=OTHER_OCI))

    _exercise_model_carrier_image_policy(lab)
    # Isolate the original missing-parameter assertion from the independent image policy.
    lab.kubectl("delete", "validatingadmissionpolicybinding", "model-carrier-image-source")

    _map(lab, [NEXT_URL])
    _check_denial(lab, "A bound update removes the previously accepted URL", _workload("Pod"), converge=True)
    _check_create(lab, "The newly approved URL is admissible after rotation", _workload("Pod", source=NEXT_URL))
    lab.kubectl("delete", "configmap", PARAM)
    _check_denial(lab, "A missing bound ConfigMap fails closed for otherwise approved input",
                   _workload("Pod", source=NEXT_URL), param_missing=True, converge=True)
    _check_create(lab, "A missing parameter does not block the outside namespace",
                  _workload("Pod", ns=OUTSIDE, source=OTHER_URL))
    (lab.evidence / "model-source-admission.json").write_text(json.dumps(
        {"checks": lab.checks, "declared_fields": [URL_VAR, OCI_VAR], "reviewed_kinds": kinds}, indent=2) + "\n")
