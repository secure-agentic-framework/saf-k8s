"""Dry-run Pod admission checks for a hostPath denial control."""
import json
from pathlib import Path
import time

HERE = Path(__file__).parent
FIXTURES = json.loads((HERE / "fixtures.json").read_text())
NAMESPACE = "saf-0304-hostpath-policy"
EXCEPTION_NAMESPACE = "saf-0304-hostpath-exception"
POLICY_VERSION = "v1.36"
DENIAL_MARKER = "violates PodSecurity"
VAP_DENIAL_MARKER = "SAF hostPath approval does not match this request"
APPROVAL_NAME = "saf-hostpath-approval-collector"
POLICY_NAME = "saf-hostpath-exception-policy"
APPROVED_IDENTITY = (
    f"system:serviceaccount:{EXCEPTION_NAMESPACE}:saf-hostpath-requester"
)
UNAPPROVED_IDENTITY = (
    f"system:serviceaccount:{EXCEPTION_NAMESPACE}:saf-hostpath-unapproved"
)
SCOPE = (
    "Server-side dry-run admission of one synthetic hostPath Pod under an "
    "unlabeled namespace and the same namespace enforcing Kubernetes v1.36 "
    "Pod Security Admission Baseline, plus a permitted emptyDir Pod dry-run. "
    "No Pod is persisted or run. No host path is created, mounted, or read. "
    "Does not test production-wide namespace coverage, admission configuration, "
    "a real infrastructure exception, policy-engine deployment, exception-register "
    "governance, or audit delivery. The supplemental case-owned ValidatingAdmissionPolicy "
    "checks one synthetic approval record and request shape; it does not establish "
    "production exception outcomes. PSA audit labels are set, but API audit events "
    "are not collected or checked."
)


def server_dry_run(lab, pod):
    """Submit only a server-side dry-run CREATE request for a fixture Pod."""
    return lab.kubectl(
        "-n", NAMESPACE,
        "create", "-f", "-", "--dry-run=server", "-o", "json",
        payload=json.dumps(pod), allow_failure=True,
    )


def server_dry_run_as(lab, pod, identity):
    """Submit a server-side dry-run as a policy-authorized fixture identity."""
    return lab.kubectl(
        "--as=" + identity,
        "-n", pod["metadata"]["namespace"],
        "create", "-f", "-", "--dry-run=server", "-o", "json",
        payload=json.dumps(pod), allow_failure=True,
    )


def create_object(lab, obj):
    """Create a case-owned policy or approval object from inline JSON."""
    namespace = obj.get("metadata", {}).get("namespace")
    args = ("-n", namespace) if namespace else ()
    return lab.kubectl(
        *args, "create", "-f", "-", payload=json.dumps(obj),
    )


def denied_for_hostpath(result):
    message = result.stderr
    return (
        result.returncode != 0
        and "(Forbidden)" in message
        and DENIAL_MARKER in message
        and f"baseline:{POLICY_VERSION}" in message
        and "hostPath volumes" in message
    )


def denied_by_exception_policy(result):
    message = result.stderr
    return (
        result.returncode != 0
        and "(Forbidden)" in message
        and "validatingadmissionpolicy" in message.lower()
        and POLICY_NAME in message
        and VAP_DENIAL_MARKER in message
    )


def denied_for_missing_approval(result):
    message = result.stderr
    return (
        result.returncode != 0
        and "validatingadmissionpolicy" in message.lower()
        and POLICY_NAME in message
        and "no params found for policy binding" in message
    )


def approval_crd():
    return {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": "hostpathapprovals.saf.example"},
        "spec": {
            "group": "saf.example",
            "scope": "Namespaced",
            "names": {
                "plural": "hostpathapprovals",
                "singular": "hostpathapproval",
                "kind": "HostPathApproval",
                "shortNames": ["hpa"],
            },
            "versions": [{
                "name": "v1",
                "served": True,
                "storage": True,
                "schema": {"openAPIV3Schema": {
                    "type": "object",
                    "required": ["spec"],
                    "properties": {"spec": {
                        "type": "object",
                        "required": [
                            "requestIdentity", "namespace", "workloadName",
                            "hostPath", "readOnly", "approvalId",
                        ],
                        "properties": {
                            "requestIdentity": {"type": "string"},
                            "namespace": {"type": "string"},
                            "workloadName": {"type": "string"},
                            "hostPath": {"type": "string"},
                            "readOnly": {"type": "boolean"},
                            "approvalId": {"type": "string"},
                            "expiresAt": {"type": "string", "format": "date-time"},
                        },
                    }},
                }},
            }],
        },
    }


def approval_record(path="/tmp/saf-hostpath-fixture"):
    return {
        "apiVersion": "saf.example/v1",
        "kind": "HostPathApproval",
        "metadata": {
            "name": APPROVAL_NAME,
            "namespace": EXCEPTION_NAMESPACE,
        },
        "spec": {
            "requestIdentity": APPROVED_IDENTITY,
            "namespace": EXCEPTION_NAMESPACE,
            "workloadName": "saf-hostpath-approved-collector",
            "hostPath": path,
            "readOnly": True,
            "approvalId": "case-record-0304-006-a",
            # Informational only: VAP CEL has no trusted current-time input.
            "expiresAt": "2099-01-01T00:00:00Z",
        },
    }


def exception_policy():
    expression = (
        "request.dryRun == true && "
        "request.userInfo.username == params.spec.requestIdentity && "
        "has(object.metadata.annotations) && "
        "object.metadata.annotations['saf.example/approval-id'] == params.spec.approvalId && "
        "object.metadata.namespace == params.spec.namespace && "
        "object.metadata.name == params.spec.workloadName && "
        "params.spec.readOnly == true && "
        "object.spec.volumes.size() == 1 && "
        "object.spec.containers.size() == 1 && "
        "(!has(object.spec.initContainers) || object.spec.initContainers.size() == 0) && "
        "object.spec.volumes.all(v, has(v.hostPath) && "
        "v.hostPath.path == params.spec.hostPath && "
        "has(v.hostPath.type) && v.hostPath.type == 'Directory') && "
        "object.spec.containers.all(c, "
        "c.volumeMounts.filter(m, m.name == object.spec.volumes[0].name).size() == 1 && "
        "c.volumeMounts.filter(m, m.name == object.spec.volumes[0].name).all(m, "
        "has(m.readOnly) && m.readOnly))"
    )
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY_NAME},
        "spec": {
            "failurePolicy": "Fail",
            "paramKind": {
                "apiVersion": "saf.example/v1",
                "kind": "HostPathApproval",
            },
            "matchConstraints": {"resourceRules": [{
                "apiGroups": [""],
                "apiVersions": ["v1"],
                "operations": ["CREATE"],
                "resources": ["pods"],
                "scope": "Namespaced",
            }]},
            "validations": [{
                "expression": expression,
                "message": VAP_DENIAL_MARKER,
                "reason": "Forbidden",
            }],
        },
    }


def exception_binding():
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": POLICY_NAME},
        "spec": {
            "policyName": POLICY_NAME,
            "validationActions": ["Deny"],
            "paramRef": {
                "name": APPROVAL_NAME,
                "namespace": EXCEPTION_NAMESPACE,
                "parameterNotFoundAction": "Deny",
            },
            "matchResources": {"namespaceSelector": {"matchLabels": {
                "saf.example/hostpath-exception": "case-owned",
            }}},
        },
    }


def admitted_pod(result, expected_name):
    if result.returncode != 0:
        return False, result.stderr.strip()
    try:
        admitted = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        return False, f"server dry-run returned invalid JSON: {error}"
    return (
        admitted.get("kind") == "Pod"
        and admitted.get("metadata", {}).get("name") == expected_name,
        {"kind": admitted.get("kind"), "name": admitted.get("metadata", {}).get("name")},
    )


def run(lab):
    hostpath = FIXTURES["hostpath_candidate"]
    permitted = FIXTURES["permitted_emptydir_candidate"]
    approved = FIXTURES["approved_hostpath_candidate"]

    # Both probes are dry-run CREATE requests. The initial namespace is created
    # without Pod Security labels to establish that the API accepts the same
    # harmless hostPath-shaped Pod before the intended admission policy applies.
    lab.kubectl("create", "namespace", NAMESPACE)
    red = server_dry_run(lab, hostpath)
    red_ok, red_observed = admitted_pod(red, hostpath["metadata"]["name"])
    lab.check(
        "red",
        "Unlabeled fixture namespace admits the hostPath-shaped server dry-run",
        red_ok,
        red_observed,
    )

    lab.kubectl(
        "label", "namespace", NAMESPACE,
        "pod-security.kubernetes.io/enforce=baseline",
        f"pod-security.kubernetes.io/enforce-version={POLICY_VERSION}",
        "pod-security.kubernetes.io/audit=baseline",
        f"pod-security.kubernetes.io/audit-version={POLICY_VERSION}",
        "pod-security.kubernetes.io/warn=baseline",
        f"pod-security.kubernetes.io/warn-version={POLICY_VERSION}",
    )
    green = server_dry_run(lab, hostpath)
    lab.check(
        "green",
        "Pinned Baseline denies the same hostPath dry-run for the hostPath reason",
        denied_for_hostpath(green),
        green.stderr.strip(),
    )

    positive = server_dry_run(lab, permitted)
    positive_ok, positive_observed = admitted_pod(
        positive, permitted["metadata"]["name"]
    )
    lab.check(
        "positive",
        "Pinned Baseline admits a harmless non-hostPath emptyDir dry-run",
        positive_ok,
        positive_observed,
    )

    # This second namespace deliberately uses PSA Privileged so native PSA does
    # not block the one exception-shaped request. The case-owned VAP binding is
    # the scoped allowlist gate. All hostPath Pod CREATE requests remain dry-runs.
    lab.kubectl("create", "namespace", EXCEPTION_NAMESPACE)
    lab.kubectl(
        "label", "namespace", EXCEPTION_NAMESPACE,
        "pod-security.kubernetes.io/enforce=privileged",
        "saf.example/hostpath-exception=case-owned",
    )
    create_object(lab, approval_crd())
    lab.kubectl(
        "wait", "--for=condition=Established", "--timeout=60s",
        "crd/hostpathapprovals.saf.example",
    )
    create_object(lab, approval_record())
    lab.kubectl(
        "create", "serviceaccount", "saf-hostpath-requester",
        "-n", EXCEPTION_NAMESPACE,
    )
    lab.kubectl(
        "create", "serviceaccount", "saf-hostpath-unapproved",
        "-n", EXCEPTION_NAMESPACE,
    )
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "hostpath-dryrun-probes", "namespace": EXCEPTION_NAMESPACE},
        "rules": [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]},
            {"apiGroups": ["saf.example"], "resources": ["hostpathapprovals"],
             "resourceNames": [APPROVAL_NAME], "verbs": ["get"]},
        ],
    }
    role_binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": "hostpath-dryrun-probes", "namespace": EXCEPTION_NAMESPACE},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": "hostpath-dryrun-probes",
        },
        "subjects": [
            {"kind": "ServiceAccount", "name": "saf-hostpath-requester", "namespace": EXCEPTION_NAMESPACE},
            {"kind": "ServiceAccount", "name": "saf-hostpath-unapproved", "namespace": EXCEPTION_NAMESPACE},
        ],
    }
    create_object(lab, role)
    create_object(lab, role_binding)
    create_object(lab, exception_policy())
    create_object(lab, exception_binding())

    def wait_for_decision(probe, identity, ready):
        for _ in range(30):
            result = server_dry_run_as(lab, probe, identity)
            if ready(result):
                return result
            time.sleep(0.5)
        lab.block("The scoped host-volume admission decision did not settle: " + result.stderr.strip())

    wait_for_decision(approved, UNAPPROVED_IDENTITY, denied_by_exception_policy)
    exception_positive = server_dry_run_as(lab, approved, APPROVED_IDENTITY)
    exception_ok, exception_observed = admitted_pod(
        exception_positive, approved["metadata"]["name"]
    )
    lab.check(
        "positive",
        "Case-approved identity and exact read-only hostPath request are admitted by server dry-run",
        exception_ok,
        exception_observed,
    )

    # A missing parameter record must fail closed at the native admission layer.
    lab.kubectl(
        "delete", "hostpathapproval", APPROVAL_NAME, "-n", EXCEPTION_NAMESPACE,
    )
    absent = wait_for_decision(approved, APPROVED_IDENTITY, denied_for_missing_approval)
    lab.check(
        "green",
        "Missing case approval is denied with the native admission reason",
        denied_for_missing_approval(absent),
        {"native_parameter_missing_denial": denied_for_missing_approval(absent)},
    )
    create_object(lab, approval_record())

    # A mismatched approval path stands in for a stale/misaligned approval. The
    # inert alternate path is never opened or mounted by a running workload.
    lab.kubectl(
        "delete", "hostpathapproval", APPROVAL_NAME, "-n", EXCEPTION_NAMESPACE,
    )
    create_object(lab, approval_record("/tmp/saf-hostpath-other"))
    mismatched = wait_for_decision(approved, APPROVED_IDENTITY, denied_by_exception_policy)
    lab.check(
        "green",
        "Mismatched approval path is denied with the native admission reason",
        denied_by_exception_policy(mismatched),
        {"native_policy_denial": denied_by_exception_policy(mismatched)},
    )
    lab.kubectl(
        "delete", "hostpathapproval", APPROVAL_NAME, "-n", EXCEPTION_NAMESPACE,
    )
    create_object(lab, approval_record())

    wait_for_decision(approved, APPROVED_IDENTITY, lambda result: result.returncode == 0)
    writable = json.loads(json.dumps(approved))
    writable["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = False
    writable_result = server_dry_run_as(lab, writable, APPROVED_IDENTITY)
    lab.check("green", "A writable mount is denied even for the approved collector identity",
              denied_by_exception_policy(writable_result),
              {"denied_by_scoped_policy": denied_by_exception_policy(writable_result)})

    unauthorized_identity = server_dry_run_as(lab, approved, UNAPPROVED_IDENTITY)
    lab.check(
        "green",
        "An RBAC-authorized but unapproved request identity is denied by native admission",
        denied_by_exception_policy(unauthorized_identity),
        {"native_policy_denial": denied_by_exception_policy(unauthorized_identity)},
    )

    unrelated = json.loads(json.dumps(approved))
    unrelated["metadata"]["name"] = "saf-hostpath-unrelated-workload"
    unrelated_result = server_dry_run_as(lab, unrelated, APPROVED_IDENTITY)
    lab.check(
        "green",
        "An unrelated workload name is denied by native admission",
        denied_by_exception_policy(unrelated_result),
        {"native_policy_denial": denied_by_exception_policy(unrelated_result)},
    )

    persisted = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pods", "-o", "json").stdout)["items"]
    exception_persisted = json.loads(
        lab.kubectl("-n", EXCEPTION_NAMESPACE, "get", "pods", "-o", "json").stdout
    )["items"]
    lab.check(
        "positive",
        "All admission probes leave no Pods in either fixture namespace",
        not persisted and not exception_persisted,
        {"policy_namespace_pods": len(persisted), "exception_namespace_pods": len(exception_persisted)},
    )
