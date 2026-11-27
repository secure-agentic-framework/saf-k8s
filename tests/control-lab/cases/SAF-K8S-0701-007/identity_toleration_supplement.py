"""Test identity-specific storage toleration admission in an isolated namespace."""
import json
import time

NAMESPACE = "saf-storage-admission"
POLICY_NAME = "saf-storage-toleration-installer-only"
BINDING_NAME = POLICY_NAME + "-binding"
ROLE_NAME = "storage-pod-creator"
APPROVED_SA = "storage-installer"
TENANT_SA = "storage-tenant"
DENIAL_MESSAGE = "reserved storage toleration requires the approved fixture identity"


def _kubectl(lab, *args, timeout=30, allow_failure=False, payload=None):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig),
        "--context", f"kind-{lab.cluster}",
        f"--request-timeout={timeout - 5}s", *args,
        payload=payload, timeout=timeout, allow_failure=allow_failure)


def _identity(name):
    return f"system:serviceaccount:{NAMESPACE}:{name}"


def _pod(name, image, node_label, taint_key):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {"saf.example/fixture": "storage-toleration-admission"}},
        "spec": {
            "restartPolicy": "Never",
            "activeDeadlineSeconds": 25,
            "terminationGracePeriodSeconds": 1,
            "automountServiceAccountToken": False,
            "serviceAccountName": APPROVED_SA,
            "nodeSelector": {node_label: "true"},
            "tolerations": [{"key": taint_key, "operator": "Equal",
                             "value": "true", "effect": "NoSchedule"}],
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "runAsGroup": 65534, "fsGroup": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "check", "image": image, "imagePullPolicy": "IfNotPresent",
                "command": ["true"],
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                              "limits": {"cpu": "100m", "memory": "32Mi"}},
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                    "runAsGroup": 65534,
                                    "allowPrivilegeEscalation": False,
                                    "privileged": False,
                                    "capabilities": {"drop": ["ALL"]},
                                    "seccompProfile": {"type": "RuntimeDefault"}},
            }],
        },
    }


def _namespace():
    return {
        "apiVersion": "v1", "kind": "Namespace",
        "metadata": {"name": NAMESPACE, "labels": {
            "pod-security.kubernetes.io/enforce": "restricted",
            "pod-security.kubernetes.io/enforce-version": "v1.36",
            "saf.example/storage-identity-boundary": "true",
        }},
    }


def _rbac_resources():
    resources = [
        {"apiVersion": "v1", "kind": "ServiceAccount",
         "metadata": {"name": name, "namespace": NAMESPACE},
         "automountServiceAccountToken": False}
        for name in (APPROVED_SA, TENANT_SA)
    ]
    resources.append({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": ROLE_NAME, "namespace": NAMESPACE},
        "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}],
    })
    resources.extend({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": name + "-pod-create", "namespace": NAMESPACE},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": ROLE_NAME},
        "subjects": [{"kind": "ServiceAccount", "name": name,
                      "namespace": NAMESPACE}],
    } for name in (APPROVED_SA, TENANT_SA))
    return resources


def _admission_resources(taint_key):
    expression = (
        f"request.userInfo.username == '{_identity(APPROVED_SA)}' || "
        "!has(object.spec.tolerations) || "
        "object.spec.tolerations.all(t, has(t.key) && "
        f"t.key != '' && t.key != '{taint_key}')"
    )
    return [
        {"apiVersion": "admissionregistration.k8s.io/v1",
         "kind": "ValidatingAdmissionPolicy",
         "metadata": {"name": POLICY_NAME},
         "spec": {
             "failurePolicy": "Fail",
             "matchConstraints": {
                 "matchPolicy": "Equivalent",
                 "resourceRules": [{
                     "apiGroups": [""], "apiVersions": ["v1"],
                     "operations": ["CREATE"], "resources": ["pods"],
                     "scope": "Namespaced",
                 }],
             },
             "validations": [{
                 "expression": expression,
                 "message": DENIAL_MESSAGE,
                 "reason": "Forbidden",
             }],
         }},
        {"apiVersion": "admissionregistration.k8s.io/v1",
         "kind": "ValidatingAdmissionPolicyBinding",
         "metadata": {"name": BINDING_NAME},
         "spec": {
             "policyName": POLICY_NAME,
             "validationActions": ["Deny"],
             "matchResources": {"namespaceSelector": {
                 "matchLabels": {"saf.example/storage-identity-boundary": "true"}}},
         }},
    ]


def _can_create(lab, principal):
    result = _kubectl(lab, "--as=" + principal, "auth", "can-i", "create", "pods",
                      "-n", NAMESPACE, timeout=20)
    return result.stdout.strip() == "yes"


def _wait_policy_typecheck(lab):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        result = _kubectl(lab, "get", "validatingadmissionpolicy", POLICY_NAME,
                          "-o", "json", timeout=15)
        policy = json.loads(result.stdout)
        type_checking = policy.get("status", {}).get("typeChecking")
        if type_checking is not None:
            warnings = type_checking.get("expressionWarnings", [])
            return not warnings, warnings
        time.sleep(0.25)
    return False, [{"warning": "bounded wait expired before policy type checking status"}]


def _create(lab, pod, principal, *, dry_run):
    flags = ["--dry-run=server"] if dry_run else []
    return _kubectl(
        lab, "--as=" + principal, "create", "-n", NAMESPACE, "-f", "-", "-o", "json",
        *flags, payload=json.dumps(pod), timeout=30, allow_failure=True)


def _wait_tenant_denial(lab, principal, pod):
    deadline = time.monotonic() + 15
    last = None
    while time.monotonic() < deadline:
        last = _create(lab, pod, principal, dry_run=True)
        detail = last.stderr.strip()
        if (last.returncode != 0 and POLICY_NAME in detail
                and DENIAL_MESSAGE in detail):
            return last
        time.sleep(0.25)
    return last


def run(lab, *, busybox_image, node_label, taint_key):
    approved_identity = _identity(APPROVED_SA)
    tenant_identity = _identity(TENANT_SA)
    try:
        _kubectl(lab, "create", "-f", "-", payload=json.dumps(_namespace()))
        for resource in _rbac_resources():
            _kubectl(lab, "create", "-f", "-", "-n", NAMESPACE,
                     payload=json.dumps(resource))
        for resource in _admission_resources(taint_key):
            _kubectl(lab, "create", "-f", "-",
                     payload=json.dumps(resource))

        policy_ok, warnings = _wait_policy_typecheck(lab)
        if not policy_ok:
            lab.block("Storage toleration admission policy failed CEL type checking")
        approved_rbac = _can_create(lab, approved_identity)
        tenant_rbac = _can_create(lab, tenant_identity)
        if not (approved_rbac and tenant_rbac):
            lab.block("Both exact fixture identities must have the same pods/create grant")

        denied_pod = _pod("storage-admission-tenant-denied", busybox_image,
                          node_label, taint_key)
        denial = _wait_tenant_denial(lab, tenant_identity, denied_pod)
        denial_text = denial.stderr.strip() if denial is not None else ""
        denial_matches = (denial is not None and denial.returncode != 0
                          and POLICY_NAME in denial_text
                          and DENIAL_MESSAGE in denial_text)
        absence = _kubectl(
            lab, "get", "pod", denied_pod["metadata"]["name"], "-n", NAMESPACE,
            "-o", "json", timeout=15, allow_failure=True)
        denied_absent = (absence.returncode != 0
                         and "NotFound" in (absence.stderr + absence.stdout))

        approved = _create(
            lab, _pod("storage-admission-approved", busybox_image, node_label, taint_key),
            approved_identity, dry_run=False)
        if approved.returncode != 0:
            lab.block("Approved storage fixture identity could not create its bounded Pod")
        created = json.loads(approved.stdout)
        _kubectl(lab, "wait", "--for=jsonpath={.status.phase}=Succeeded",
                 "pod/storage-admission-approved", "-n", NAMESPACE,
                 "--timeout=40s", timeout=50)
        persisted = json.loads(_kubectl(
            lab, "get", "pod", "storage-admission-approved", "-n", NAMESPACE,
            "-o", "json").stdout)
        node = persisted.get("spec", {}).get("nodeName", "")
        pod_list = json.loads(_kubectl(
            lab, "get", "pods", "-n", NAMESPACE, "-o", "json").stdout).get("items", [])
        only_owned_pod = (
            len(pod_list) == 1
            and pod_list[0].get("metadata", {}).get("name") == "storage-admission-approved"
            and bool(persisted.get("metadata", {}).get("uid"))
            and created.get("metadata", {}).get("uid") == persisted.get("metadata", {}).get("uid")
        )
        container = persisted.get("spec", {}).get("containers", [{}])[0]
        tolerations = persisted.get("spec", {}).get("tolerations", [])
        nonprivileged = (
            container.get("image") == busybox_image
            and container.get("command") == ["true"]
            and container.get("securityContext", {}).get("privileged") is False
            and container.get("securityContext", {}).get("allowPrivilegeEscalation") is False
            and not persisted.get("spec", {}).get("volumes")
            and persisted.get("metadata", {}).get("namespace") == NAMESPACE
            and persisted.get("spec", {}).get("serviceAccountName") == APPROVED_SA
            and persisted.get("spec", {}).get("automountServiceAccountToken") is False
        )
        expected_toleration = {"key": taint_key, "operator": "Equal",
                               "value": "true", "effect": "NoSchedule"}
        exact_reserved_toleration = [
            toleration for toleration in tolerations if toleration.get("key") == taint_key
        ] == [expected_toleration]
        allowed_ok = (
            approved_rbac and approved.returncode == 0
            and created.get("metadata", {}).get("name") == "storage-admission-approved"
            and created.get("metadata", {}).get("namespace") == NAMESPACE
            and persisted.get("status", {}).get("phase") == "Succeeded"
            and node == f"{lab.cluster}-worker"
            and exact_reserved_toleration
            and nonprivileged and only_owned_pod
        )
        denied_ok = tenant_rbac and denial_matches and denied_absent
        raw = {
            "scope": "case-owned VAP and namespaced RBAC; one approved tokenless Pod; tenant comparator is server-side dry-run only",
            "namespace": NAMESPACE,
            "policy": {"name": POLICY_NAME, "typecheck_ok": policy_ok,
                       "expression_warnings": warnings},
            "principals": {"approved": approved_identity, "tenant": tenant_identity},
            "rbac_create_pods": {"approved": approved_rbac, "tenant": tenant_rbac},
            "approved_create": {"returncode": approved.returncode,
                                "pod_uid": persisted.get("metadata", {}).get("uid"),
                                "phase": persisted.get("status", {}).get("phase"),
                                "node": node, "tolerations": tolerations,
                                "nonprivileged": nonprivileged,
                                "only_expected_pod_and_uid_bound": only_owned_pod},
            "tenant_dry_run": {"returncode": denial.returncode if denial else None,
                               "policy_specific_denial": denial_matches,
                               "pod_absent_after_dry_run": denied_absent,
                               "detail": denial_text},
        }
        (lab.evidence / "storage-toleration-admission.raw.json").write_text(
            json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        lab.check(
            "positive",
            "Native admission allows the approved identity and denies a tenant with identical pods/create RBAC from self-requesting the reserved storage toleration",
            allowed_ok and denied_ok,
            {"policy_typechecked": policy_ok,
             "both_fixture_identities_have_pods_create": approved_rbac and tenant_rbac,
             "approved_identity_created_one_bounded_nonprivileged_pod": allowed_ok,
             "tenant_create_was_policy_denied_and_not_persisted": denied_ok,
             "same_reserved_toleration": exact_reserved_toleration})
    finally:
        for kind, name in (("validatingadmissionpolicybinding", BINDING_NAME),
                           ("validatingadmissionpolicy", POLICY_NAME)):
            _kubectl(lab, "delete", kind, name, "--ignore-not-found=true",
                     "--wait=true", "--timeout=20s", timeout=25, allow_failure=True)
        _kubectl(lab, "delete", "namespace", NAMESPACE, "--ignore-not-found=true",
                 "--wait=true", "--timeout=25s", timeout=30, allow_failure=True)
