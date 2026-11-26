"""Run one scoped API review action as the fixture's real service-account identity."""
import json
from pathlib import Path
import ssl
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen


ROOT = Path("/fixture")
TOKEN_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
API = "https://kubernetes.default.svc"
NS = "saf-test"
RB = "rbac.authorization.k8s.io"


def request(method, path, body=None):
    token = (TOKEN_DIR / "token").read_text().strip()
    headers = {"Authorization": "Bearer " + token}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/merge-patch+json"
        data = json.dumps(body).encode()
    req = Request(API + path, data=data, headers=headers, method=method)
    context = ssl.create_default_context(cafile=str(TOKEN_DIR / "ca.crt"))
    try:
        with urlopen(req, context=context, timeout=8) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except HTTPError as error:
        error.read()
        return error.code, {}


def group_subject(name):
    return {"kind": "Group", "apiGroup": RB, "name": name}


def main():
    mode = sys.argv[1]
    policy = json.loads((ROOT / "approved-entitlement.json").read_text())
    target_path = f"/apis/{RB}/v1/namespaces/{NS}/rolebindings/{policy['target']}"
    baseline_path = f"/apis/{RB}/v1/namespaces/{NS}/rolebindings/{policy['unrelated_binding']}"
    policy_path = f"/api/v1/namespaces/{NS}/configmaps/approved-entitlement"
    expected = group_subject(policy["approved_group"])

    if mode == "reconcile":
        status, current = request("GET", target_path)
        if status != 200:
            raise RuntimeError(f"target read returned {status}")
        subjects = current.get("subjects", [])
        role_ref = current.get("roleRef", {})
        if (subjects != [group_subject(policy["stale_group"])]
                or role_ref.get("kind") != "Role" or role_ref.get("name") != policy["target"]):
            raise RuntimeError("owned binding differs from the expected stale fixture")
        patch = {"metadata": {"resourceVersion": current["metadata"]["resourceVersion"]},
                 "subjects": [expected]}
        write_status, _ = request("PATCH", target_path, patch)
        if write_status != 200:
            raise RuntimeError(f"approved remediation returned {write_status}")
        read_status, updated = request("GET", target_path)
        persisted = (read_status == 200 and updated.get("subjects") == [expected]
                     and updated.get("roleRef") == role_ref)
        print(json.dumps({"operation": mode, "http_status": write_status,
                          "persisted": persisted,
                          "resource_version_changed": read_status == 200 and
                          updated["metadata"]["resourceVersion"] != current["metadata"]["resourceVersion"]}),
              flush=True)
        if not persisted:
            raise RuntimeError("approved binding subjects did not persist")
        return

    if mode == "deny-target":
        status, _ = request("PATCH", target_path,
                            {"subjects": [group_subject(policy["stale_group"])]})
        print(json.dumps({"operation": mode, "http_status": status, "denied": status == 403}), flush=True)
        if status != 403:
            raise RuntimeError("unapproved service account was not denied")
        return

    if mode == "deny-scope-policy":
        unrelated_status, _ = request("PATCH", baseline_path, {"subjects": [expected]})
        policy_status, _ = request("PATCH", policy_path, {"data": {"approved_group": "changed"}})
        result = {"operation": mode, "unrelated_http_status": unrelated_status,
                  "policy_http_status": policy_status,
                  "unrelated_denied": unrelated_status == 403, "policy_denied": policy_status == 403}
        print(json.dumps(result), flush=True)
        if unrelated_status != 403 or policy_status != 403:
            raise RuntimeError("fixture review identity exceeded its approved scope")
        return

    raise RuntimeError("unknown fixture review operation")


if __name__ == "__main__":
    main()
