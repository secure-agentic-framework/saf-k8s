"""Synthetic dry-run-only legacy-token exception oracle for SAF-K8S-0103-001.

Additive companion for the current case. This module may only be called with
that lab harness's owned disposable kind cluster. Secret candidates are never
persisted, and no token data, TokenRequest, Pods, Roles, or RBAC bindings are
created.
"""
import json
import time

NAMESPACE = "saf-legacy-exception-oracle"
POLICY = "saf-legacy-exception-oracle"
BINDING = "saf-legacy-exception-oracle"
PARAMS = "saf-legacy-exception-oracle"
SECRET_NAME = "saf-approved-legacy-token"
SERVICE_ACCOUNT = "saf-approved-service-account"
APPROVAL_ID = "synthetic-approval-0103-001"
EXPIRES_AT = "2030-01-01T00:00:00Z"
BEFORE = "2029-12-31T23:59:59Z"
AT_EXPIRY = EXPIRES_AT
AFTER = "2030-01-01T00:00:01Z"
TOKEN_TYPE = "kubernetes.io/service-account-token"

POLICY_MESSAGE = "legacy token exception is not approved and unexpired"

POLICY_AND_BINDING = f"""apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: {POLICY}
spec:
  failurePolicy: Fail
  paramKind:
    apiVersion: v1
    kind: ConfigMap
  matchConstraints:
    resourceRules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      operations: ["CREATE"]
      resources: ["secrets"]
  validations:
  - expression: >-
      object.type != '{TOKEN_TYPE}' ||
      (params != null &&
       request.namespace == params.data['namespace'] &&
       object.metadata.name == params.data['secretName'] &&
       'kubernetes.io/service-account.name' in object.metadata.annotations &&
       object.metadata.annotations['kubernetes.io/service-account.name'] == params.data['serviceAccount'] &&
       'saf-k8s.example/exception-id' in object.metadata.annotations &&
       object.metadata.annotations['saf-k8s.example/exception-id'] == params.data['approvalId'] &&
       'saf-k8s.example/expires-at' in object.metadata.annotations &&
       object.metadata.annotations['saf-k8s.example/expires-at'] == params.data['expiresAt'] &&
       params.data['expiresAt'] > params.data['now'])
    message: "{POLICY_MESSAGE}"
    reason: Forbidden
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: {BINDING}
spec:
  policyName: {POLICY}
  validationActions: [Deny]
  paramRef:
    name: {PARAMS}
    namespace: {NAMESPACE}
    parameterNotFoundAction: Deny
  matchResources:
    namespaceSelector:
      matchLabels:
        saf-k8s.example/exception-oracle: "enabled"
"""


def kubectl(lab, *args, payload=None, allow_failure=False, timeout=20):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
        f"kind-{lab.cluster}", f"--request-timeout=15s", *args,
        timeout=timeout, payload=payload, allow_failure=allow_failure,
    )


def parameter(now):
    # Canonical UTC RFC3339 timestamps have fixed-width lexical ordering.
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": PARAMS, "namespace": NAMESPACE},
        "data": {
            "namespace": NAMESPACE,
            "secretName": SECRET_NAME,
            "serviceAccount": SERVICE_ACCOUNT,
            "approvalId": APPROVAL_ID,
            "expiresAt": EXPIRES_AT,
            "now": now,
        },
    }


def token_secret(*, name=SECRET_NAME, service_account=SERVICE_ACCOUNT,
                 approval_id=APPROVAL_ID, expires_at=EXPIRES_AT):
    # Intentionally metadata-only. No data/stringData or token bytes exist.
    return {
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "annotations": {
                "kubernetes.io/service-account.name": service_account,
                "saf-k8s.example/exception-id": approval_id,
                "saf-k8s.example/expires-at": expires_at,
            },
        },
        "type": TOKEN_TYPE,
    }


def token_secret_without_approval():
    obj = token_secret()
    obj["metadata"]["annotations"] = {
        "kubernetes.io/service-account.name": SERVICE_ACCOUNT,
    }
    return obj


def update_clock(lab, now):
    kubectl(lab, "apply", "-f", "-", payload=json.dumps(parameter(now)))


def candidate_result(lab, obj, expected_allow):
    # No response body or error is copied to receipt; only booleans are retained.
    if "data" in obj or "stringData" in obj:
        lab.block("Synthetic token Secret must contain no credential fields")
    deadline = time.monotonic() + 15
    matched = False
    while True:
        result = kubectl(
            lab, "create", "-f", "-", "--dry-run=server", "-o", "name",
            payload=json.dumps(obj), allow_failure=True,
        )
        if expected_allow:
            matched = result.returncode == 0
        else:
            matched = (result.returncode != 0 and POLICY in result.stderr
                       and POLICY_MESSAGE in result.stderr)
        if matched or time.monotonic() >= deadline:
            break
        # Retries remain server-side dry-run; no candidate is stored.
        time.sleep(0.5)
    # Prove that API server dry-run did not persist this candidate. A failure
    # other than NotFound is not accepted as cleanup evidence.
    absent = kubectl(
        lab, "-n", NAMESPACE, "get", f"secret/{obj['metadata']['name']}",
        "-o", "name", allow_failure=True,
    )
    not_found = absent.returncode != 0 and "NotFound" in absent.stderr
    token_rows = kubectl(
        lab, "-n", NAMESPACE, "get", "secrets",
        "-o", "custom-columns=TYPE:.type", "--no-headers",
    ).stdout.splitlines()
    no_token_secrets = all(row.strip() != TOKEN_TYPE for row in token_rows)
    return matched, not_found, no_token_secrets


def observe(lab, claim, obj, expected_allow):
    matched, not_found, no_token_secrets = candidate_result(lab, obj, expected_allow)
    lab.check(
        "positive" if expected_allow else "green",
        claim,
        matched and not_found and no_token_secrets,
        {
            "dry_run_admission_matched": matched,
            "candidate_secret_not_found": not_found,
            "namespace_has_zero_legacy_token_secrets": no_token_secrets,
            "secret_data_fields_present": False,
        },
    )


def run(lab):
    """Run only from the 0103-001 harness inside its owned disposable kind lab."""
    if not getattr(lab, "cluster", "").startswith("saf-lab-"):
        lab.block("Refusing exception oracle outside the case-owned saf-lab kind cluster")
    existing = kubectl(lab, "get", f"namespace/{NAMESPACE}", allow_failure=True)
    if existing.returncode == 0:
        lab.block(f"Case namespace already exists: {NAMESPACE}")
    for kind, name in (("validatingadmissionpolicy", POLICY),
                       ("validatingadmissionpolicybinding", BINDING)):
        result = kubectl(lab, "get", f"{kind}/{name}", allow_failure=True)
        if result.returncode == 0:
            lab.block(f"Case policy resource already exists: {kind}/{name}")

    kubectl(lab, "create", "namespace", NAMESPACE)
    kubectl(lab, "label", "namespace", NAMESPACE,
            "saf-k8s.example/exception-oracle=enabled")
    kubectl(lab, "apply", "-f", "-", payload=POLICY_AND_BINDING)
    update_clock(lab, BEFORE)

    approved = token_secret()
    observe(lab, "Unlisted Secret name is denied before the approved comparison",
            token_secret(name="saf-unlisted-legacy-token"), False)
    observe(lab, "Exact synthetic approved exception is admitted before expiry",
            approved, True)

    for now, label in ((AT_EXPIRY, "at"), (AFTER, "after")):
        update_clock(lab, now)
        observe(lab, f"Exact exception is denied {label} modeled expiry",
                approved, False)

    update_clock(lab, BEFORE)
    observe(lab, "The approved tuple is admitted again when restored to the valid modeled window",
            approved, True)
    variants = [
        (token_secret(service_account="saf-other-service-account"),
         "Wrong ServiceAccount subject is denied"),
        (token_secret(approval_id="unapproved-reference"),
         "Wrong approval reference is denied"),
        (token_secret(expires_at="malformed-expiry"),
         "Expiry value differing from the approved record is denied"),
        (token_secret_without_approval(),
         "Missing approval and expiry metadata is denied"),
    ]
    for candidate, claim in variants:
        observe(lab, claim, candidate, False)

    harmless = {
        "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
        "metadata": {"name": "saf-harmless-opaque", "namespace": NAMESPACE},
    }
    observe(lab, "Ordinary opaque Secret remains admitted by this policy",
            harmless, True)

    # The only created objects are a fixture Namespace, VAP, binding, and
    # non-secret ConfigMap cutoff parameter. The policy does not create roles.
    # Clean policy resources before removing their namespace.
    kubectl(lab, "delete", "validatingadmissionpolicybinding", BINDING,
            "--wait=true")
    kubectl(lab, "delete", "validatingadmissionpolicy", POLICY,
            "--wait=true")
    kubectl(lab, "delete", "namespace", NAMESPACE, "--wait=true", timeout=90)
