"""Native VAP parameter gate for the existing 0602-001 keyless fixture.

This module does NOT perform signature verification. The trusted test
orchestrator calls it only after the existing Cosign verify command returned
zero for the complete exact digest and the private Rekor/TSA/Fulcio evidence
was checked. That typed handoff is an explicit fixture trust boundary.
"""
import json
import re
import time

NS = "saf-test"
APPROVED = "saf-0602-001-approved-image"
LAUNCHER = "system:serviceaccount:saf-test:saf-0602-001-launcher"
CONTROLLER = "system:serviceaccount:saf-test:saf-0602-001-review-controller"
POD_POLICY = "saf-0602-001-exact-approved-image"
RECORD_POLICY = "saf-0602-001-approved-record-author"


def _policy(name, *, resource, operations, expression, param_kind=None):
    spec = {
        "failurePolicy": "Fail",
        "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                  "operations": operations, "resources": [resource]}]},
        "validations": [{"expression": expression, "message": "0602-001 fixture trust gate rejected request",
                         "reason": "Forbidden"}],
    }
    if param_kind:
        spec["paramKind"] = param_kind
    return {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": name}, "spec": spec}


def _binding(name, policy, *, params_name=None, namespace=NS):
    spec = {"policyName": policy, "validationActions": ["Deny"],
            "matchResources": {"namespaceSelector": {"matchLabels": {
                "kubernetes.io/metadata.name": namespace}}}}
    if params_name:
        spec["paramRef"] = {"name": params_name, "namespace": namespace,
                            "parameterNotFoundAction": "Deny"}
    return {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": name}, "spec": spec}


def _pod(name, image):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "containers": [{"name": "inert", "image": image,
                                     "command": ["/bin/echo", "0602-001-admission-fixture"]}]}}


def _submit(lab, pod):
    return lab.kubectl(f"--as={LAUNCHER}", "create", "-f", "-", "--dry-run=server",
                       payload=json.dumps(pod), allow_failure=True)


def _eventually(lab, attempt, matches, description):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        result = attempt()
        if matches(result):
            return result
        time.sleep(0.4)
    lab.block(description)


def _policy_denial(result, policy):
    return result.returncode != 0 and policy in result.stderr and "denied request" in result.stderr


def run(lab, *, ref, verification_result):
    """Call after existing Cosign verification; append five native observations."""
    digest = ref.rsplit("@", 1)[-1]
    expected = {
        "ref": ref,
        "identity": "https://kubernetes.io/namespaces/saf-test/serviceaccounts/saf-0602-001-signer",
        "issuer": "https://kubernetes.default.svc.cluster.local",
        "cosign_exit_code": 0,
        "private_rekor_inclusion_proof": True,
        "timestamp_present": True,
        "fulcio_leaf_present": True,
    }
    if not isinstance(verification_result, dict) or verification_result != expected:
        raise ValueError("VAP fixture requires the exact successful keyless verification result")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("the approved image must be a digest-qualified OCI reference")

    # Separate fixture identities. The test runner impersonates the controller
    # only for the approval creation request; namespace RBAC and VAP constrain it.
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {
        "name": "saf-0602-001-review-controller", "namespace": NS}})
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {
        "name": "saf-0602-001-launcher", "namespace": NS}})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {
        "name": "saf-0602-001-review-controller", "namespace": NS}, "rules": [{
        "apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {
        "name": "saf-0602-001-review-controller", "namespace": NS}, "subjects": [{
        "kind": "ServiceAccount", "name": "saf-0602-001-review-controller", "namespace": NS}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": "saf-0602-001-review-controller"}})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {
        "name": "saf-0602-001-launcher", "namespace": NS}, "rules": [{
        "apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {
        "name": "saf-0602-001-launcher", "namespace": NS}, "subjects": [{
        "kind": "ServiceAccount", "name": "saf-0602-001-launcher", "namespace": NS}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": "saf-0602-001-launcher"}})

    # Only the named controller can create the immutable review record. This
    # validates the fixture author identity, record name, and digest shape;
    # it does not validate the Sigstore proof itself.
    author_expr = (f'request.userInfo.username == "{CONTROLLER}" && '
                   f'object.metadata.name == "{APPROVED}" && object.immutable == true && '
                   'has(object.data) && "approvedImage" in object.data && '
                   'object.data.approvedImage.matches("^[^@]+@sha256:[a-f0-9]{64}$")')
    lab.create(_policy(RECORD_POLICY, resource="configmaps", operations=["CREATE"],
                       expression=author_expr))
    lab.create(_binding(RECORD_POLICY + "-binding", RECORD_POLICY))

    image_expr = ("params != null && has(params.data) && "
                  '"approvedImage" in params.data && '
                  "object.spec.containers.all(c, c.image == params.data.approvedImage) && "
                  "(!has(object.spec.initContainers) || "
                  "object.spec.initContainers.all(c, c.image == params.data.approvedImage))")
    lab.create(_policy(POD_POLICY, resource="pods", operations=["CREATE"],
                       expression=image_expr,
                       param_kind={"apiVersion": "v1", "kind": "ConfigMap"}))
    lab.create(_binding(POD_POLICY + "-binding", POD_POLICY, params_name=APPROVED))

    probe = _pod("saf-0602-001-no-approval", ref)
    def missing_approval(result):
        return _policy_denial(result, POD_POLICY) and "no params found for policy binding" in result.stderr

    absent = _eventually(lab, lambda: _submit(lab, probe), missing_approval,
                         "Pod admission did not reject the missing approval parameter")
    lab.check("green", "Native VAP denies the Pod while the approval parameter is absent",
              missing_approval(absent),
              {"request_rejected": True, "parameter_object_present": False})

    # The test orchestrator creates only after checking the typed result above.
    # Kubernetes confirms the request is authorized as the distinct reviewer SA;
    # the VAP confirms exact record name/author/immutability/digest shape.
    record = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
        "name": APPROVED, "namespace": NS, "labels": {"saf.example/0602-001-approval": "fixture"}},
        "immutable": True, "data": {"approvedImage": ref}}
    author_refused = _eventually(lab, lambda: lab.create(record, dry_run=True, allow_failure=True),
                                 lambda r: _policy_denial(r, RECORD_POLICY),
                                 "The author policy did not reject an approval from the wrong identity")
    create = lab.kubectl(f"--as={CONTROLLER}", "create", "-f", "-", "-o", "json",
                         payload=json.dumps(record), allow_failure=True)
    if create.returncode:
        lab.block("The scoped review-controller identity could not create the exact approval record: "
                  + create.stderr.strip())
    stored = json.loads(lab.kubectl("get", "configmap", APPROVED, "-o", "json").stdout)
    record_ok = (stored.get("immutable") is True and stored.get("data", {}).get("approvedImage") == ref
                 and stored["metadata"].get("name") == APPROVED)
    lab.check("positive", "Scoped fixture review controller creates the exact immutable digest record",
              record_ok and _policy_denial(author_refused, RECORD_POLICY),
              {"exact_digest_record": record_ok, "fixture_controller_request_succeeded": True,
               "wrong_author_rejected_by_policy": True})

    accepted = _eventually(lab, lambda: _submit(lab, _pod("saf-0602-001-exact-digest", ref)),
                           lambda r: r.returncode == 0,
                           "The exact approved image did not become admissible")
    wrong = ref.rsplit("@", 1)[0] + "@sha256:" + ("0" * 64 if digest != "sha256:" + "0" * 64 else "1" * 64)
    denied = _submit(lab, _pod("saf-0602-001-wrong-digest", wrong))
    matched_deny = _policy_denial(denied, POD_POLICY) and "fixture trust gate rejected" in denied.stderr
    lab.check("green", "Native VAP denies a digest different from the pinned approval parameter",
              matched_deny, {"different_digest_rejected": matched_deny})
    lab.check("positive", "Native VAP accepts the exact locally verified digest",
              accepted.returncode == 0,
              {"exact_digest_admitted": accepted.returncode == 0, "server_dry_run": True})

    # An unrelated launcher cannot create, update or delete the record. Test
    # authorization separately; immutability is an additional API safeguard.
    can_create = lab.kubectl("auth", "can-i", "create", "configmaps", "-n", NS,
                             f"--as={LAUNCHER}", allow_failure=True)
    can_update = lab.kubectl("auth", "can-i", "update", f"configmap/{APPROVED}", "-n", NS,
                             f"--as={LAUNCHER}", allow_failure=True)
    can_delete = lab.kubectl("auth", "can-i", "delete", f"configmap/{APPROVED}", "-n", NS,
                             f"--as={LAUNCHER}", allow_failure=True)
    tamper = lab.kubectl(f"--as={LAUNCHER}", "patch", "configmap", APPROVED,
                         "--type=merge", "-p", json.dumps({"data": {"approvedImage": wrong}}),
                         allow_failure=True)
    lab.check("green", "Unprivileged launcher cannot create, update, delete, or alter approval",
           can_create.stdout.strip() == "no" and can_update.stdout.strip() == "no"
           and can_delete.stdout.strip() == "no" and tamper.returncode != 0,
           {"create_authorized": can_create.stdout.strip() == "yes",
            "update_authorized": can_update.stdout.strip() == "yes",
            "delete_authorized": can_delete.stdout.strip() == "yes",
            "patch_rejected": tamper.returncode != 0})
