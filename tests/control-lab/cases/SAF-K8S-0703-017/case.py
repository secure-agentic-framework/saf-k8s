"""Restrict fixture PriorityClass references at actual Pod admission."""

import json
import time

SCOPE = "Two owned namespaces, two fixture service accounts and Kubernetes native PriorityClass admission."
IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
STANDARD = "saf-priority-standard"
RESERVED = "saf-priority-reserved"
LOW = "saf-priority-normal"
HIGH = "saf-priority-elevated"
POLICY = "saf-fixture-priority"
RULE = "explicit PriorityClass must match the fixture namespace profile"


def create(lab, resource, *, namespace=None, user_namespace=None, dry=False, allow_failure=False):
    flags = ("-n", namespace) if namespace else ()
    if user_namespace:
        flags += ("--as", f"system:serviceaccount:{user_namespace}:submitter")
    if dry:
        flags += ("--dry-run=server",)
    result = lab.kubectl(*flags, "create", "-f", "-", "-o", "json", payload=json.dumps(resource),
                         allow_failure=allow_failure)
    return result if allow_failure else json.loads(result.stdout)


def namespace_identity(lab, namespace):
    create(lab, {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace,
                 "labels": {"pod-security.kubernetes.io/enforce": "restricted"}}})
    create(lab, {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "submitter"},
                 "automountServiceAccountToken": False}, namespace=namespace)
    create(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "submit"},
                 "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]},
                           {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["create"]}]}, namespace=namespace)
    create(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "submit"},
                 "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "submit"},
                 "subjects": [{"kind": "ServiceAccount", "name": "submitter", "namespace": namespace}]}, namespace=namespace)


def pod_spec(priority):
    spec = {"automountServiceAccountToken": False, "securityContext": {
                "runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "fixture", "image": IMAGE, "command": ["/bin/sleep", "180"],
                            "resources": {"requests": {"cpu": "5m", "memory": "4Mi"},
                                          "limits": {"cpu": "100m", "memory": "24Mi"}},
                            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                "capabilities": {"drop": ["ALL"]}}}]}
    if priority:
        spec["priorityClassName"] = priority
    return spec


def pod(name, priority):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": pod_spec(priority)}


def deployment(name, priority):
    labels = {"saf.example/pod": name}
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
            "spec": {"replicas": 1, "selector": {"matchLabels": labels}, "template": {"metadata": {"labels": labels},
                     "spec": pod_spec(priority)}}}


def submit(lab, resource, *, namespace=STANDARD, user_namespace=STANDARD, dry=True, allow_failure=False):
    return create(lab, resource, namespace=namespace, user_namespace=user_namespace, dry=dry,
                  allow_failure=allow_failure)


def policy(lab):
    expr = (f"has(object.spec.priorityClassName) && ((request.namespace == '{STANDARD}' && "
            f"object.spec.priorityClassName == '{LOW}') || (request.namespace == '{RESERVED}' && "
            f"object.spec.priorityClassName == '{HIGH}'))")
    create(lab, {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
                 "metadata": {"name": POLICY}, "spec": {"failurePolicy": "Fail", "matchConstraints": {
                     "resourceRules": [{"operations": ["CREATE", "UPDATE"], "apiGroups": [""], "apiVersions": ["v1"],
                                        "resources": ["pods"], "scope": "Namespaced"}]},
                     "validations": [{"expression": expr, "message": RULE}]}})
    create(lab, {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
                 "metadata": {"name": POLICY}, "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                     "matchResources": {"namespaceSelector": {"matchExpressions": [
                         {"key": "kubernetes.io/metadata.name", "operator": "In", "values": [STANDARD, RESERVED]}]}}}})


def denied(result):
    return result.returncode != 0 and POLICY in result.stderr and RULE in result.stderr


def run(lab):
    for namespace in (STANDARD, RESERVED):
        namespace_identity(lab, namespace)
    for priority, value in ((LOW, 10), (HIGH, 2000)):
        create(lab, {"apiVersion": "scheduling.k8s.io/v1", "kind": "PriorityClass", "metadata": {"name": priority},
                     "value": value, "globalDefault": False, "preemptionPolicy": "Never"})
    class_get = lab.kubectl("--as", f"system:serviceaccount:{STANDARD}:submitter", "get", "priorityclass", HIGH,
                            allow_failure=True)
    baseline = submit(lab, pod("same-submission", HIGH))
    separate = class_get.returncode != 0 and "Forbidden" in class_get.stderr
    lab.check("red", "Class-object RBAC denies the read while built-in admission resolves a valid class reference",
              separate and baseline["spec"]["priority"] == 2000,
              {"class_object_read_forbidden": separate, "elevated_reference_resolved_before_policy": True})
    policy(lab)
    limit = time.monotonic() + 40
    while time.monotonic() < limit:
        if denied(submit(lab, pod("same-submission", HIGH), allow_failure=True)):
            break
        time.sleep(1)
    else:
        lab.block("The fixture PriorityClass binding did not converge")
    no_class = denied(submit(lab, pod("unspecified-class", None), allow_failure=True))
    other_namespace = submit(lab, pod("other-namespace", HIGH), namespace=RESERVED, allow_failure=True)
    boundary = other_namespace.returncode != 0 and "cannot create resource" in other_namespace.stderr and "Forbidden" in other_namespace.stderr
    lab.check("green", "Explicit namespace admission denies elevated and omitted classes while RBAC isolates submitters",
              no_class and boundary, {"wrong_class_denied": True, "omitted_class_denied": no_class, "other_namespace_forbidden": boundary})
    submit(lab, deployment("denied-priority-workload", HIGH), dry=False)
    lab.kubectl("-n", STANDARD, "wait", "--for=condition=ReplicaFailure", "deployment/denied-priority-workload",
                "--timeout=45s", timeout=55)
    blocked = json.loads(lab.kubectl("-n", STANDARD, "get", "deployment", "denied-priority-workload", "-o", "json").stdout)
    details = blocked["status"].get("conditions", [])
    failed_create = any(row.get("reason") == "FailedCreate" and RULE in row.get("message", "") for row in details)
    pods = lab.kubectl("-n", STANDARD, "get", "pods", "-l", "saf.example/pod=denied-priority-workload", "-o", "name").stdout
    lab.check("green", "A controller-created Pod with a disallowed PriorityClass is also refused",
              failed_create and not pods.strip(), {"controller_admission_denial": failed_create, "no_pod_created": not pods.strip()})
    low = submit(lab, pod("approved-normal", LOW))
    high = submit(lab, pod("approved-elevated", HIGH), namespace=RESERVED, user_namespace=RESERVED, dry=False)
    lab.kubectl("-n", RESERVED, "wait", "--for=condition=Ready", "pod/approved-elevated", "--timeout=65s", timeout=75)
    confirmed = low["spec"]["priority"] == 10 and high["spec"]["priority"] == 2000
    lab.check("positive", "Allowlisted classes are accepted and the authorized elevated fixture starts",
              confirmed, {"approved_class_values_resolved": confirmed, "elevated_fixture_ready": True})
    (lab.evidence / "priority-admission-observations.json").write_text(json.dumps({
        "rbac_denies_class_read": separate, "restricted_namespace_denials": no_class and boundary,
        "controller_failed_creation": failed_create, "approved_priority_values": confirmed,
    }, indent=2) + "\n")
