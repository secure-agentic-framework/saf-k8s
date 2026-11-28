"""Admission policy and response check shared by the owned MIG tests."""

import re

RESOURCE = "nvidia.com/mig-1g.5gb"
RUN_LABEL = "fixture.saf.example/mig-proof"
DENIAL = "This fixture requires the approved MIG profile"


def objects(namespace, name, run):
    api = "admissionregistration.k8s.io/v1"
    check = ("object.spec.runtimeClassName == 'nvidia' && "
             "(!has(object.spec.nodeName) || object.spec.nodeName == '') && "
             "object.spec.containers.size() == 1 && object.spec.containers.all(c, "
             "has(c.resources) && has(dyn(c.resources).limits) && "
             f"'{RESOURCE}' in dyn(c.resources).limits && !('nvidia.com/gpu' in dyn(c.resources).limits) && "
             "(!has(dyn(c.resources).requests) || !('nvidia.com/gpu' in dyn(c.resources).requests)))")
    common = {"apiVersion": api, "metadata": {"name": name, "labels": {RUN_LABEL: run}}}
    return (
        {**common, "kind": "ValidatingAdmissionPolicy",
         "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [
             {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]}]},
             "validations": [{"expression": check, "message": DENIAL, "reason": "Forbidden"}]}},
        {**common, "kind": "ValidatingAdmissionPolicyBinding",
         "spec": {"policyName": name, "validationActions": ["Deny"], "matchResources": {
             "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
             "objectSelector": {"matchLabels": {RUN_LABEL: run}}}}})


def exact_denial(result, pod, policy):
    pod_name = re.escape(f'pods "{pod}" is forbidden: ')
    decision = re.escape(f"ValidatingAdmissionPolicy '{policy}' with binding '{policy}' denied request: {DENIAL}")
    return result.returncode != 0 and any(re.fullmatch(
        r'Error from server \(Forbidden\): (?:error when creating "STDIN": )?'
        + pod_name + r"(?:: )?" + decision,
        line.strip()) for line in result.stderr.splitlines())
