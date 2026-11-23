"""Admission-only fixture for governance of AWS LBC NLB frontend SG selection.

This exercises Kubernetes API admission only. It does not install AWS Load
Balancer Controller, provision a cloud load balancer, or assert network reachability.
"""
import json
import time


SCOPE = (
    "Kubernetes Services of type LoadBalancer with spec.loadBalancerClass="
    "service.k8s.aws/nlb, reconciled by AWS Load Balancer Controller v3.2, "
    "using one externally governed AWS security-group ID in the frontend "
    "security-groups annotation. Admission only; no cloud behavior is tested."
)

ANNOTATION = "service.beta.kubernetes.io/aws-load-balancer-security-groups"
APPROVED_A = "sg-0123456789abcdef0"
APPROVED_B = "sg-abcdef01234567890"
UNAPPROVED = "sg-11111111111111111"
POLICY_NAME = "aws-nlb-approved-frontend-security-group"
BINDING_NAME = "aws-nlb-approved-frontend-security-group-binding"


def _apply(lab, resource):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(resource))


def _service(name, group_id, *, labels=None):
    metadata = {"name": name, "annotations": {ANNOTATION: group_id}}
    if labels is not None:
        metadata["labels"] = labels
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": metadata,
        "spec": {
            "type": "LoadBalancer",
            "loadBalancerClass": "service.k8s.aws/nlb",
            "ports": [{"name": "tcp", "port": 443, "targetPort": 8443}],
            "selector": {"app": "admission-fixture"},
        },
    }


def _governance_resources():
    crd = {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": "awsfrontendsecuritygroupallowlists.governance.example.com"},
        "spec": {
            "group": "governance.example.com",
            "scope": "Namespaced",
            "names": {
                "plural": "awsfrontendsecuritygroupallowlists",
                "singular": "awsfrontendsecuritygroupallowlist",
                "kind": "AwsFrontendSecurityGroupAllowlist",
                "shortNames": ["awsfsgallow"],
            },
            "versions": [{
                "name": "v1alpha1",
                "served": True,
                "storage": True,
                "schema": {"openAPIV3Schema": {
                    "type": "object",
                    "required": ["spec"],
                    "properties": {"spec": {
                        "type": "object",
                        "required": ["groupIDs"],
                        "properties": {"groupIDs": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 16,
                            "items": {
                                "type": "string",
                                "maxLength": 20,
                                "pattern": "^sg-[0-9a-f]{8}([0-9a-f]{9})?$",
                            },
                        }},
                    }},
                }},
            }],
        },
    }
    parameter = {
        "apiVersion": "governance.example.com/v1alpha1",
        "kind": "AwsFrontendSecurityGroupAllowlist",
        "metadata": {"name": "production-nlb-frontends", "namespace": "saf-test"},
        "spec": {"groupIDs": [APPROVED_A, APPROVED_B]},
    }
    policy = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY_NAME},
        "spec": {
            "failurePolicy": "Fail",
            "paramKind": {
                "apiVersion": "governance.example.com/v1alpha1",
                "kind": "AwsFrontendSecurityGroupAllowlist",
            },
            "matchConstraints": {"resourceRules": [{
                "apiGroups": [""],
                "apiVersions": ["v1"],
                "operations": ["CREATE", "UPDATE"],
                "resources": ["services"],
            }]},
            "validations": [{
                "expression": (
                    "object.spec.type != 'LoadBalancer' || "
                    "!has(object.spec.loadBalancerClass) || "
                    "object.spec.loadBalancerClass != 'service.k8s.aws/nlb' || "
                    "(has(object.metadata.annotations) && "
                    f"'{ANNOTATION}' in object.metadata.annotations && "
                    f"!object.metadata.annotations['{ANNOTATION}'].contains(',') && "
                    f"params.spec.groupIDs.exists(id, id == object.metadata.annotations['{ANNOTATION}']))"
                ),
                "message": (
                    f"{ANNOTATION} must contain exactly one AWS security-group ID "
                    "from the separately governed allowlist"
                ),
                "reason": "Forbidden",
            }],
        },
    }
    binding = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": BINDING_NAME},
        "spec": {
            "policyName": POLICY_NAME,
            "matchResources": {"namespaceSelector": {
                "matchLabels": {"saf-k8s.example/control": "0503-006"}}},
            "paramRef": {
                "name": "production-nlb-frontends",
                "namespace": "saf-test",
                "parameterNotFoundAction": "Deny",
            },
            "validationActions": ["Deny"],
        },
    }
    return crd, parameter, policy, binding


WRITER = "system:serviceaccount:saf-test:service-writer"
PARAM_KIND = "awsfrontendsecuritygroupallowlist.governance.example.com"
PARAM_NAME = "production-nlb-frontends"
DENIAL = f"{ANNOTATION} must contain exactly one AWS security-group ID from the separately governed allowlist"


def _api(lab, *args, payload=None, allow_failure=False):
    return lab.kubectl(*args, f"--as={WRITER}", payload=payload, allow_failure=allow_failure)


def _writer_role(lab):
    lab.kubectl("create", "serviceaccount", "service-writer")
    _apply(lab, {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "saf-service-writer", "namespace": "saf-test"},
        "rules": [
            {"apiGroups": [""], "resources": ["services"],
             "verbs": ["create", "get", "update", "delete"]},
            {"apiGroups": ["governance.example.com"], "resources": ["awsfrontendsecuritygroupallowlists"],
             "resourceNames": [PARAM_NAME], "verbs": ["get"]},
        ],
    })
    lab.kubectl("create", "rolebinding", "saf-service-writer", "--role=saf-service-writer",
                "--serviceaccount=saf-test:service-writer")


def _submit(lab, verb, obj, *, dry_run=False):
    args = [verb, "-f", "-", "-o", "json"]
    if dry_run:
        args.append("--dry-run=server")
    return _api(lab, *args, payload=json.dumps(obj), allow_failure=True)


def _expect_created(lab, phase, name, group):
    result = _submit(lab, "create", _service(name, group))
    stored = json.loads(result.stdout) if result.returncode == 0 else {}
    checks = {
        "is_service": stored.get("kind") == "Service",
        "stored_group_matched": stored.get("metadata", {}).get("annotations", {}).get(ANNOTATION) == group,
        "owned_class_matched": stored.get("spec", {}).get("loadBalancerClass") == "service.k8s.aws/nlb",
    }
    lab.check(phase, f"Real Service create stored the expected group for {name}", all(checks.values()), checks)
    return stored


def _denial(result):
    output = result.stdout + result.stderr
    return {
        "api_rejected": result.returncode != 0,
        "policy_matched": f"ValidatingAdmissionPolicy '{POLICY_NAME}'" in output,
        "binding_matched": f"binding '{BINDING_NAME}'" in output,
        "message_matched": DENIAL in output,
    }


def _expect_denied(lab, claim, verb, obj):
    observed = _denial(_submit(lab, verb, obj))
    lab.check("green", claim, all(observed.values()), observed)


def _wait_for_policy(lab, probe):
    deadline = time.monotonic() + 35
    while True:
        if all(_denial(_submit(lab, "create", probe, dry_run=True)).values()):
            return
        if time.monotonic() >= deadline:
            lab.block("The named parameterized policy and binding did not become active")
        time.sleep(0.5)


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "saf-k8s.example/control=0503-006")
    crd, parameter, policy, binding = _governance_resources()
    _apply(lab, crd)
    lab.kubectl("wait", "--for=condition=Established",
                "crd/awsfrontendsecuritygroupallowlists.governance.example.com", "--timeout=30s")
    _apply(lab, parameter)
    _writer_role(lab)

    # The fixture writer can read an approved parameter, while the actual API
    # forbids the same writer from changing it.
    original = json.loads(_api(lab, "get", PARAM_KIND, PARAM_NAME, "-o", "json").stdout)
    change = _api(lab, "patch", PARAM_KIND, PARAM_NAME, "--type=merge", "-p",
                  json.dumps({"spec": {"groupIDs": [UNAPPROVED]}}), allow_failure=True)
    parameter_protected = ("Forbidden" in change.stderr and change.returncode != 0
                           and original["spec"]["groupIDs"] == [APPROVED_A, APPROVED_B])
    lab.check("positive", "Scoped Service writer can read the governed list and cannot change it",
              parameter_protected, {"allowlist_read_only_for_service_writer": parameter_protected})

    name = "unapproved-nlb"
    probe = _service(name, UNAPPROVED)
    _expect_created(lab, "red", name, UNAPPROVED)
    _api(lab, "delete", "service", name, "--wait=true")

    _apply(lab, policy)
    _apply(lab, binding)
    _wait_for_policy(lab, probe)
    _expect_denied(lab, "The same unapproved group is rejected by the live policy", "create", probe)
    _expect_denied(lab, "Mixing an approved and an unapproved group is rejected by the live policy",
                   "create", _service("mixed", f"{APPROVED_A},{UNAPPROVED}"))
    without_annotation = _service("unannotated", APPROVED_A)
    without_annotation["metadata"].pop("annotations")
    _expect_denied(lab, "Missing frontend group selection is rejected by the live policy",
                   "create", without_annotation)

    allowed = _expect_created(lab, "positive", "approved-nlb", APPROVED_A)
    allowed["metadata"]["annotations"][ANNOTATION] = UNAPPROVED
    _expect_denied(lab, "Replacing a stored approved group with an unapproved group is rejected",
                   "replace", allowed)
    persisted = json.loads(_api(lab, "get", "service", "approved-nlb", "-o", "json").stdout)
    still_approved = persisted["metadata"]["annotations"][ANNOTATION] == APPROVED_A
    lab.check("positive", "Denied update leaves the original group on the stored Service",
              still_approved, {"original_group_preserved": still_approved})
    persisted["metadata"]["annotations"][ANNOTATION] = APPROVED_B
    result = _submit(lab, "replace", persisted)
    updated = json.loads(result.stdout) if result.returncode == 0 else {}
    matched = updated.get("metadata", {}).get("annotations", {}).get(ANNOTATION) == APPROVED_B
    lab.check("positive", "A different approved group remains eligible for a real Service update",
              matched, {"updated_group_approved": matched})
