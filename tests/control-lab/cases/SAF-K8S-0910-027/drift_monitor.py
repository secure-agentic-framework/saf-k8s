"""One-shot in-cluster monitor for the owned SAF-K8S-0910-027 binding."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.request

NS = "saf-test"
BINDING = "fixture-no-hostnetwork-binding"
REVISION_ANNOTATION = "saf-k8s.example/desired-revision"
TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


def request(method, path, body=None):
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    url = f"https://{host}:{port}{path}"
    token = Path(TOKEN_PATH).read_text().strip()
    data = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/merge-patch+json" if method == "PATCH" else "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    context = ssl.create_default_context(cafile=CA_PATH)
    with urllib.request.urlopen(req, context=context, timeout=12) as response:
        return json.loads(response.read())


def main():
    desired = os.environ["EXPECTED_REVISION"]
    member_uid = os.environ["MEMBER_UID"]
    binding_path = f"/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/{BINDING}"
    current = request("GET", binding_path)
    before_revision = current.get("metadata", {}).get("annotations", {}).get(REVISION_ANNOTATION)
    before_actions = current.get("spec", {}).get("validationActions", [])
    if before_revision == desired and before_actions == ["Deny"]:
        raise RuntimeError("fixture expected the scheduled pass to observe its injected drift")
    patch = {"metadata": {"resourceVersion": current["metadata"]["resourceVersion"],
                           "annotations": {REVISION_ANNOTATION: desired}},
             "spec": {"validationActions": ["Deny"]}}
    request("PATCH", binding_path, patch)
    verified = request("GET", binding_path)
    after_revision = verified.get("metadata", {}).get("annotations", {}).get(REVISION_ANNOTATION)
    after_actions = verified.get("spec", {}).get("validationActions", [])
    repaired = after_revision == desired and after_actions == ["Deny"]
    if not repaired:
        raise RuntimeError("scheduled reconciliation readback did not match the selected desired revision")
    job_name = os.environ["JOB_NAME"]
    alert_name = "fixture-drift-alert-" + job_name[-35:]
    alert = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "immutable": True,
        "metadata": {"name": alert_name, "namespace": NS,
                     "labels": {"saf-k8s.example/fixture": "0910-027", "saf-k8s.example/type": "drift-alert"}},
        "data": {
            "event": "admission-policy-binding-drift-repaired",
            "member_uid": member_uid,
            "binding": BINDING,
            "desired_revision": desired,
            "observed_revision": before_revision or "missing",
            "observed_actions": json.dumps(before_actions, separators=(",", ":")),
            "repaired_revision": after_revision,
            "repaired_actions": json.dumps(after_actions, separators=(",", ":")),
            "detected_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "repair_verified": "true"
        }
    }
    request("POST", f"/api/v1/namespaces/{NS}/configmaps", alert)
    print(json.dumps({"decision": "drift-repaired", "alert": alert_name,
                      "repair_verified": repaired}, sort_keys=True))


if __name__ == "__main__":
    main()
