"""Verify a documented local authorization path from a mapped fixture group."""

import json
import importlib.util
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
OIDC_SPEC = importlib.util.spec_from_file_location("saf_0704_015_oidc_bridge", HERE / "oidc_bridge.py")
oidc_bridge = importlib.util.module_from_spec(OIDC_SPEC)
OIDC_SPEC.loader.exec_module(oidc_bridge)

SCOPE = "Synthetic identity mapping and live Kubernetes RBAC plus a case-owned native OIDC JWT path for owned markers."
NAMESPACE = "saf-test"
ALLOWED = "entitlement-approved"
COMPARISON = "entitlement-comparison"
READER = "fixture-user-entitlement-reader"
GROUP = "fixture-group-entitlement-readers"
ROLE = "fixture-entitlement-read"
PRINCIPAL = "fixture:iam:report-reader"
MARKER = "approved-public-marker"


def read_marker(lab, user, group, name):
    result = lab.kubectl("--as", user, "--as-group", group, "get", "configmap", name,
                         "-o", "json", allow_failure=True)
    if result.returncode == 0:
        return json.loads(result.stdout)["data"]["marker"]
    if "(Forbidden)" in result.stderr and name in result.stderr:
        return "forbidden"
    lab.block("Unexpected response from the owned marker read")


def install_grant(lab):
    group_api = "rbac.authorization.k8s.io"
    lab.create({"apiVersion": f"{group_api}/v1", "kind": "Role", "metadata": {"name": ROLE},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [ALLOWED],
                           "verbs": ["get"]}]})
    lab.create({"apiVersion": f"{group_api}/v1", "kind": "RoleBinding", "metadata": {"name": ROLE},
                "roleRef": {"apiGroup": group_api, "kind": "Role", "name": ROLE},
                "subjects": [{"kind": "Group", "apiGroup": group_api, "name": GROUP}]})


def run(lab):
    for name, marker in ((ALLOWED, MARKER), (COMPARISON, "comparison-public-marker")):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                    "data": {"marker": marker}})
    existing = json.loads(lab.kubectl("get", "configmap", ALLOWED, "-o", "json").stdout)
    before = read_marker(lab, READER, GROUP, ALLOWED)
    lab.check("red", "The approved fixture identity attributes do not grant access without the documented binding",
              existing["data"]["marker"] == MARKER and before == "forbidden",
              {"marker_exists": existing["data"]["marker"] == MARKER, "before_binding": before})

    install_grant(lab)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        after = read_marker(lab, READER, GROUP, ALLOWED)
        if after == MARKER:
            break
        time.sleep(0.4)
    else:
        lab.block("The installed fixture binding did not grant the approved read")
    live_grant = json.loads(lab.kubectl("get", "rolebinding", ROLE, "-o", "json").stdout)
    subject_verified = live_grant["subjects"][0]["name"] == GROUP and live_grant["roleRef"]["name"] == ROLE
    lab.check("green", "The fixture inventory resolves to the installed binding and the live API serves the approved marker",
              subject_verified and after == MARKER, {"named_binding_matches": subject_verified, "approved_read": after == MARKER})

    comparison = read_marker(lab, READER, GROUP, COMPARISON)
    unrelated = read_marker(lab, "fixture-user-unrelated", "fixture-group-unrelated", ALLOWED)
    lab.check("positive", "The unrelated fixture identity and the additional fixture object remain outside the named grant",
              comparison == unrelated == "forbidden",
              {"comparison_object": comparison, "unrelated_identity": unrelated})
    observations = {"principal": PRINCIPAL, "external_identity_is_synthetic": True, "local_user": READER,
                    "local_group": GROUP, "authorizer": "Kubernetes RBAC", "namespace": NAMESPACE, "role_binding": ROLE,
                    "before_binding": before, "approved_read": after == MARKER,
                    "comparison_object": comparison, "unrelated_identity": unrelated}
    (lab.evidence / "entitlement-observations.json").write_text(json.dumps(observations, indent=2) + "\n")
    oidc_bridge.run_native_oidc_checks(lab, here=HERE)
