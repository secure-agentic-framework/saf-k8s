"""Check one exact Pod-to-PVC admission boundary with server-side dry-runs only."""
import json
from pathlib import Path
import time


NAMESPACE = "saf-test"
CLAIM = "saf-rwo-workspace"
APPROVED = "saf-k8s:0701-001-approved-claim-user"
UNAPPROVED = "saf-k8s:0701-001-unapproved-claim-user"
POLICY = "saf-k8s-0701-001-pod-claim-reference"
DENIAL = "only the approved fixture identity may reference the protected PVC"


def pod_request(name, claim=None):
    spec = {
        "automountServiceAccountToken": False,
        "containers": [{"name": "dry-run", "image": "registry.k8s.io/pause:3.10.1"}],
    }
    if claim:
        spec["volumes"] = [{"name": "protected", "persistentVolumeClaim": {"claimName": claim}}]
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": NAMESPACE}, "spec": spec}


def pod_create_dry_run(lab, user, request):
    return lab.kubectl(
        "--as", user, "-n", NAMESPACE, "create", "-f", "-",
        "--dry-run=server", "-o", "json", payload=json.dumps(request),
        allow_failure=True,
    )


def exact_policy_denial(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and f"ValidatingAdmissionPolicy '{POLICY}'" in result.stderr
            and DENIAL in result.stderr)


def create_minimal_pod_create_grant(lab):
    """Give only the two synthetic users Pod CREATE so admission is evaluated."""
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "saf-0701-001-pod-create", "namespace": NAMESPACE},
        "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}],
    }
    binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": "saf-0701-001-pod-create", "namespace": NAMESPACE},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": "saf-0701-001-pod-create"},
        "subjects": [
            {"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": APPROVED},
            {"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": UNAPPROVED},
        ],
    }
    lab.kubectl("create", "-f", "-", payload=json.dumps(role))
    lab.kubectl("create", "-f", "-", payload=json.dumps(binding))


def run(lab):
    # The original case already created and bound this one exact protected PVC,
    # and labeled only this case namespace. Do not create another claim.
    existing = json.loads(lab.kubectl("get", "pvc", "-o", "json").stdout)["items"]
    names = sorted(row.get("metadata", {}).get("name") for row in existing)
    if names != [CLAIM] or existing[0].get("metadata", {}).get("namespace") != NAMESPACE:
        lab.block(f"Expected exactly one protected fixture PVC in {NAMESPACE}; observed {names}")

    create_minimal_pod_create_grant(lab)
    protected = pod_request("saf-0701-001-reference-protected", CLAIM)
    ordinary = pod_request("saf-0701-001-reference-ordinary")

    baseline = pod_create_dry_run(lab, UNAPPROVED, protected)
    lab.check(
        "red", "Before reference policy, an authorized synthetic caller can dry-run a Pod referencing the protected claim",
        baseline.returncode == 0,
        {"server_side_dry_run_admitted": baseline.returncode == 0,
         "persisted_pod": False, "claim": CLAIM, "identity": UNAPPROVED},
    )

    lab.apply(Path(__file__).with_name("pod-claim-reference-policy.yaml"))
    deadline = time.monotonic() + 15
    while True:
        denied = pod_create_dry_run(lab, UNAPPROVED, protected)
        approved = pod_create_dry_run(lab, APPROVED, protected)
        ordinary_allowed = pod_create_dry_run(lab, UNAPPROVED, ordinary)
        outcomes = (exact_policy_denial(denied), approved.returncode == 0,
                    ordinary_allowed.returncode == 0)
        if all(outcomes) or time.monotonic() >= deadline:
            break
        time.sleep(0.25)

    lab.check(
        "green", "The exact policy denies an unrelated identity's protected PVC reference",
        exact_policy_denial(denied),
        {"policy_denial": exact_policy_denial(denied), "identity": UNAPPROVED,
         "claim": CLAIM, "persisted_pod": False},
    )
    lab.check(
        "positive", "The fixed approved identity may dry-run reference the protected PVC",
        approved.returncode == 0,
        {"server_side_dry_run_admitted": approved.returncode == 0,
         "identity": APPROVED, "claim": CLAIM, "persisted_pod": False},
    )
    lab.check(
        "positive", "An ordinary no-claim Pod remains admitted for the unrelated identity",
        ordinary_allowed.returncode == 0,
        {"server_side_dry_run_admitted": ordinary_allowed.returncode == 0,
         "identity": UNAPPROVED, "protected_claim_referenced": False,
         "persisted_pod": False},
    )
