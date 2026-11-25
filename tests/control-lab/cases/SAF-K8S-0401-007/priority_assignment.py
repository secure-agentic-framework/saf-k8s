"""Check the Pod priorityClassName assignment boundary with scoped admission."""
import base64
import ipaddress
import json
from pathlib import Path
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import yaml


NAMESPACE = "saf-0401-007-priority-assignment"
WORKLOAD = "saf-0401-007-workload"
ASSIGNER = "saf-0401-007-priority-assigner"
POLICY = "saf-0401-007-priority-assignment"
BINDING = "saf-0401-007-priority-assignment-binding"
ORDINARY_CLASS = "saf-0401-007-low"
GOVERNED_CLASS = "system-cluster-critical"
ORDINARY_PRIORITY = 100
GOVERNED_PRIORITY = 2_000_000_000


def kubectl(lab, *args, payload=None, timeout=30, allow_failure=False):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", "kind-" + lab.cluster,
        "--namespace", NAMESPACE, f"--request-timeout={timeout - 5}s", *args,
        payload=payload, timeout=timeout, allow_failure=allow_failure,
    )


def create(lab, resource):
    return kubectl(lab, "create", "-f", "-", "-o", "json",
                   payload=json.dumps(resource, sort_keys=True, separators=(",", ":")))


def api_transport(lab):
    config_path = Path(lab.kubeconfig)
    config = yaml.safe_load(config_path.read_text())
    context_name = "kind-" + lab.cluster
    contexts = {row["name"]: row["context"] for row in config.get("contexts", [])}
    context = contexts.get(context_name)
    if not context:
        lab.block("Could not resolve the owned Kind API context for the VAP probe")
    clusters = {row["name"]: row["cluster"] for row in config.get("clusters", [])}
    cluster = clusters.get(context.get("cluster"))
    if not cluster or not cluster.get("server"):
        lab.block("Could not resolve the owned Kind API endpoint for the VAP probe")
    try:
        endpoint = urlsplit(cluster["server"])
        local_address = ipaddress.ip_address(endpoint.hostname)
        ca_pem = base64.b64decode(cluster["certificate-authority-data"], validate=True).decode("ascii")
    except (KeyError, TypeError, ValueError):
        lab.block("The owned Kind API context lacks a valid endpoint and embedded CA")
    if endpoint.scheme != "https" or not local_address.is_loopback or not endpoint.port:
        lab.block("Priority policy probes require the runner-owned loopback HTTPS API")
    return cluster["server"].rstrip("/"), ssl.create_default_context(cadata=ca_pem)


def service_account_token(lab, name):
    try:
        result = subprocess.run(
            ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", "kind-" + lab.cluster,
             "-n", NAMESPACE, "create", "token", name, "--duration=10m"],
            env=lab.env, text=True, capture_output=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        lab.block("Could not mint a bounded synthetic ServiceAccount token")
    token = result.stdout.strip()
    if result.returncode or token.count(".") != 2:
        lab.block("Could not mint a bounded synthetic ServiceAccount token")
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (ValueError, json.JSONDecodeError):
        lab.block("The synthetic ServiceAccount token subject was not parseable")
    expected = "system:serviceaccount:%s:%s" % (NAMESPACE, name)
    if claims.get("sub") != expected:
        lab.block("The synthetic ServiceAccount token did not identify the requested subject")
    return token, expected


def dry_run_pod(server, tls, token, name, priority_class=None):
    pod_spec = {"containers": [{"name": "synthetic", "image": "example.invalid/saf/never-pulled:fixture"}]}
    if priority_class is not None:
        pod_spec["priorityClassName"] = priority_class
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": name, "namespace": NAMESPACE,
                        "labels": {"saf-k8s.example/fixture": "priority-assignment-dry-run"}},
           "spec": pod_spec}
    url = "%s/api/v1/namespaces/%s/pods?dryRun=All" % (server, NAMESPACE)
    request = urllib.request.Request(
        url, data=json.dumps(pod).encode("utf-8"), method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, context=tls, timeout=8) as response:
            body = json.load(response)
            spec = body.get("spec", {})
            return {"status": response.status, "priority_class": spec.get("priorityClassName", ""),
                    "priority": spec.get("priority"), "policy_denial": False}
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8", errors="replace"))
        except (ValueError, UnicodeDecodeError):
            body = {}
        message = body.get("message", "")
        return {"status": exc.code, "priority_class": priority_class or "", "priority": None,
                "policy_denial": POLICY in message and BINDING in message and body.get("reason") == "Forbidden"}
    except (OSError, TimeoutError):
        return {"status": 0, "priority_class": priority_class or "", "priority": None,
                "policy_denial": False}


def namespace_and_identities(lab):
    create(lab, {"apiVersion": "v1", "kind": "Namespace",
                 "metadata": {"name": NAMESPACE,
                              "labels": {"saf-k8s.example/fixture": "priority-assignment-only"}}})
    for name in (WORKLOAD, ASSIGNER):
        create(lab, {"apiVersion": "v1", "kind": "ServiceAccount",
                     "metadata": {"name": name, "namespace": NAMESPACE},
                     "automountServiceAccountToken": False})
        role_name = name + "-pod-create"
        create(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                     "metadata": {"name": role_name, "namespace": NAMESPACE},
                     "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]})
        create(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                     "metadata": {"name": role_name, "namespace": NAMESPACE},
                     "subjects": [{"kind": "ServiceAccount", "name": name, "namespace": NAMESPACE}],
                     "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                                 "name": role_name}})


def policy_objects():
    expression = (
        "!has(object.spec.priorityClassName) || object.spec.priorityClassName == '' || "
        "object.spec.priorityClassName == '%s' || "
        "(object.spec.priorityClassName == '%s' && "
        "request.userInfo.username == 'system:serviceaccount:%s:%s')"
    ) % (ORDINARY_CLASS, GOVERNED_CLASS, NAMESPACE, ASSIGNER)
    policy = {
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {"resourceRules": [{
                "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"],
                "resources": ["pods"], "scope": "Namespaced",
            }]},
            "validations": [{"expression": expression,
                             "message": "Only the authorized synthetic identity may assign the governed class",
                             "reason": "Forbidden"}],
        },
    }
    binding = {
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": BINDING},
        "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                 "matchResources": {"namespaceSelector": {"matchLabels": {
                     "saf-k8s.example/fixture": "priority-assignment-only"}}}},
    }
    return policy, binding


def policy_typecheck_is_clean(lab):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        result = json.loads(kubectl(lab, "get", "validatingadmissionpolicy/" + POLICY,
                                    "-o", "json", timeout=10).stdout)
        checking = result.get("status", {}).get("typeChecking")
        if checking is not None:
            return not checking.get("expressionWarnings", [])
        time.sleep(0.25)
    return False


def binding_is_namespace_scoped(lab):
    result = json.loads(kubectl(lab, "get", "validatingadmissionpolicybinding/" + BINDING,
                                "-o", "json").stdout)
    selector = result.get("spec", {}).get("matchResources", {}).get("namespaceSelector", {})
    return (result.get("spec", {}).get("policyName") == POLICY
            and result.get("spec", {}).get("validationActions") == ["Deny"]
            and selector.get("matchLabels") == {
                "saf-k8s.example/fixture": "priority-assignment-only"})


def run(lab):
    server, tls = api_transport(lab)
    try:
        namespace_and_identities(lab)
        workload_token, workload_subject = service_account_token(lab, WORKLOAD)
        assigner_token, assigner_subject = service_account_token(lab, ASSIGNER)
        # Red baseline: before a binding exists, both the approved assigner and
        # ordinary workload identity can submit the governed class in dry-run.
        baseline_assigner = dry_run_pod(server, tls, assigner_token, "baseline-approved-governed",
                                        GOVERNED_CLASS)
        baseline_workload = dry_run_pod(server, tls, workload_token, "baseline-workload-governed",
                                        GOVERNED_CLASS)
        baseline_ok = (workload_subject == "system:serviceaccount:%s:%s" % (NAMESPACE, WORKLOAD)
                       and assigner_subject == "system:serviceaccount:%s:%s" % (NAMESPACE, ASSIGNER)
                       and baseline_assigner["status"] == 201
                       and baseline_assigner["priority"] == GOVERNED_PRIORITY
                       and baseline_workload["status"] == 201
                       and baseline_workload["priority"] == GOVERNED_PRIORITY)
        lab.check("red", "Before policy binding, the synthetic actors can dry-run the governed class",
                  baseline_ok,
                  {"approved_subject_matches": workload_subject.endswith(":" + WORKLOAD)
                   and assigner_subject.endswith(":" + ASSIGNER),
                   "approved_actor_dry_run_accepted": baseline_assigner["status"] == 201,
                   "unapproved_actor_dry_run_accepted_before_policy": baseline_workload["status"] == 201,
                   "governed_priority_resolved": baseline_assigner["priority"] == GOVERNED_PRIORITY})

        policy, binding = policy_objects()
        create(lab, policy)
        create(lab, binding)
        typed = policy_typecheck_is_clean(lab)
        scoped = binding_is_namespace_scoped(lab)

        approved = dry_run_pod(server, tls, assigner_token, "green-approved-governed", GOVERNED_CLASS)
        deadline = time.monotonic() + 15
        while True:
            denied = dry_run_pod(server, tls, workload_token, "green-workload-governed", GOVERNED_CLASS)
            if denied["policy_denial"] or time.monotonic() >= deadline:
                break
            time.sleep(0.25)
        ordinary = dry_run_pod(server, tls, workload_token, "green-workload-ordinary", ORDINARY_CLASS)
        defaulted = dry_run_pod(server, tls, workload_token, "green-workload-default")
        green = (
            typed and scoped and approved["status"] == 201
            and approved["priority_class"] == GOVERNED_CLASS
            and approved["priority"] == GOVERNED_PRIORITY
            and denied["status"] == 403 and denied["policy_denial"]
            and ordinary["status"] == 201 and ordinary["priority_class"] == ORDINARY_CLASS
            and ordinary["priority"] == ORDINARY_PRIORITY
            and defaulted["status"] == 201 and defaulted["priority_class"] == ""
            and defaulted["priority"] == 0
        )
        lab.check("green", "The namespace policy denies unapproved governed assignment and preserves permitted/default classes",
                  green,
                  {"policy_typecheck_clean": typed,
                   "binding_selects_only_owned_fixture_namespace": scoped,
                   "approved_governed_assignment_allowed": approved["status"] == 201
                   and approved["priority"] == GOVERNED_PRIORITY,
                   "unapproved_governed_assignment_denied_by_policy": denied["status"] == 403
                   and denied["policy_denial"],
                   "ordinary_class_assignment_allowed": ordinary["status"] == 201
                   and ordinary["priority"] == ORDINARY_PRIORITY,
                   "no_class_default_remains_zero": defaulted["status"] == 201
                   and defaulted["priority"] == 0,
                   "all_pod_requests_were_server_side_dry_run": True})
    finally:
        cleanup(lab)


def cleanup(lab):
    kubectl(lab, "delete", "validatingadmissionpolicybinding/" + BINDING,
            "--ignore-not-found=true", timeout=20, allow_failure=True)
    kubectl(lab, "delete", "validatingadmissionpolicy/" + POLICY,
            "--ignore-not-found=true", timeout=20, allow_failure=True)
    deleted = kubectl(lab, "delete", "namespace/" + NAMESPACE,
                      "--ignore-not-found=true", timeout=45, allow_failure=True)
    if deleted.returncode:
        lab.block("Could not confirm cleanup of the owned priority assignment fixture")
