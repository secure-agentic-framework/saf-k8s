"""Observe tenant label and role subject policies on ordinary API requests."""
import json
from pathlib import Path
import time

from fixtures import BUSYBOX_IMAGE
import yaml


HERE = Path(__file__).parent
TENANT = "saf-0702-025-tenant-a"
OTHER = "saf-0702-025-tenant-b"
DEPLOYMENT = "saf-0702-025-accepted"
ROLE = "saf-tenant-fixture-reader"
BINDING = "saf-tenant-binding"
SCOPE = (
    "Kubernetes v1.36.1 validates tenant metadata on Deployment CREATE/UPDATE, and "
    "same-namespace ServiceAccount references on namespaced RoleBinding CREATE/UPDATE. "
    "Checks use administrator-owned synthetic fixtures, server-side dry-run for mismatches "
    "and API-persisted known-good objects. Actual deployment policy enrollment, additional "
    "tenant resource references, identities and privileged shared-service exceptions "
    "require production evidence."
)
LABEL_POLICY = ("saf-k8s-0702-025-tenant-labels", "saf-k8s-0702-025-enrolled",
                "tenant resource and Pod template tenant IDs must match the enrolled namespace")
ROLE_POLICY = ("saf-k8s-0702-025-rolebinding-subjects", "saf-k8s-0702-025-enrolled-rolebinding",
               "tenant RoleBinding ServiceAccount subjects must belong to this namespace")


def deployment(filename):
    item = yaml.safe_load((HERE / filename).read_text())
    item["spec"]["template"]["spec"]["containers"][0]["image"] = BUSYBOX_IMAGE
    item["spec"]["template"]["spec"]["automountServiceAccountToken"] = False
    return item


def apply_object(lab, item, *, replace=False, dry=False):
    cmd = "replace" if replace else "create"
    args = ("--dry-run=server",) if dry else ()
    return lab.kubectl("-n", TENANT, cmd, "-f", "-", *args, payload=json.dumps(item),
                       allow_failure=dry)


def rolebinding(name, namespace):
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": name, "namespace": TENANT},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ROLE},
        "subjects": [{"kind": "ServiceAccount", "name": "fixture-owner", "namespace": namespace}],
    }


def matching_denial(result, policy):
    name, binding, reason = policy
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and f"ValidatingAdmissionPolicy '{name}'" in result.stderr
            and f"binding '{binding}'" in result.stderr and reason in result.stderr)


def run(lab):
    lab.apply(HERE / "enrollment.yaml")
    lab.kubectl("create", "namespace", OTHER)
    for namespace in (TENANT, OTHER):
        lab.kubectl("-n", namespace, "create", "serviceaccount", "fixture-owner")
    lab.kubectl("-n", TENANT, "create", "role", ROLE,
                "--verb=get", "--resource=configmaps", "--resource-name=fixture-marker")
    apply_object(lab, deployment("accepted-deployment.yaml"))
    apply_object(lab, rolebinding(BINDING, TENANT))

    fixtures = (
        ("deployment-create", deployment("invalid-deployment-create.yaml"), False, LABEL_POLICY),
        ("deployment-update", deployment("invalid-deployment-update.yaml"), True, LABEL_POLICY),
        ("rolebinding-create", rolebinding("saf-mismatch-binding", OTHER), False, ROLE_POLICY),
        ("rolebinding-update", rolebinding(BINDING, OTHER), True, ROLE_POLICY),
    )
    baseline = {label: apply_object(lab, item, replace=replace, dry=True).returncode == 0
                for label, item, replace, _ in fixtures}
    lab.check("red", "The API admits all four invalid declaration dry-runs before enrollment policy",
              all(baseline.values()), baseline)

    lab.apply(HERE / "admission-policy.yaml")
    deadline = time.monotonic() + 25
    while True:
        results = {label: matching_denial(apply_object(lab, item, replace=replace, dry=True), policy)
                   for label, item, replace, policy in fixtures}
        if all(results.values()) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("green", "The enrolled policies deny mismatched workload owners and cross-namespace subjects on CREATE and UPDATE",
              all(results.values()), results)

    admitted = deployment("accepted-deployment.yaml")
    admitted["metadata"]["name"] = "saf-0702-025-accepted-after"
    apply_object(lab, admitted)
    apply_object(lab, rolebinding("saf-tenant-binding-after", TENANT))
    existing = json.loads(lab.kubectl("-n", TENANT, "get", "deployment",
                                      DEPLOYMENT, "-o", "json").stdout)
    original = json.loads(lab.kubectl("-n", TENANT, "get", "rolebinding",
                                      BINDING, "-o", "json").stdout)
    valid_after = (existing["spec"]["template"]["metadata"]["labels"]["saf-k8s.example/tenant-id"] == "tenant-a"
                   and original["subjects"][0]["namespace"] == TENANT)
    lab.check("positive", "Matching objects are accepted and the rejected updates leave the saved declarations unchanged",
              valid_after, {"matching_deployment_create": True, "matching_binding_create": True,
                            "saved_declarations_unchanged": valid_after})
