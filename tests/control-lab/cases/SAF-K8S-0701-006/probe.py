"""Submit one predetermined API operation with this fixture Pod's own identity."""
from http.client import HTTPSConnection
import json
from pathlib import Path
import ssl
import sys

MOUNT = Path("/var/run/secrets/kubernetes.io/serviceaccount")
action = sys.argv[1]
args = sys.argv[2:]
pv_name = args[0] if len(args) > 0 else "synthetic-retained-archive"
ledger_name = args[1] if len(args) > 1 else "saf-approval-ledger"
namespace = "saf-test"
PV = f"/api/v1/persistentvolumes/{pv_name}"
PVC = f"/api/v1/namespaces/{namespace}/persistentvolumeclaims/saf-retained-volume-claim"
LEDGER = f"/api/v1/namespaces/{namespace}/configmaps/{ledger_name}"
JOBS = f"/apis/batch/v1/namespaces/{namespace}/jobs"
JOB = JOBS + "/saf-approved-marker-removal"
IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
JOB_OBJECT = {
    "apiVersion": "batch/v1", "kind": "Job",
    "metadata": {"name": "saf-approved-marker-removal", "namespace": namespace},
    "spec": {
        "backoffLimit": 0, "activeDeadlineSeconds": 30, "ttlSecondsAfterFinished": 300,
        "template": {
            "metadata": {"labels": {"saf-k8s.example/fixture": "0701-006"}},
            "spec": {
                "restartPolicy": "Never", "serviceAccountName": "fixture-executor",
                "automountServiceAccountToken": False,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{
                    "name": "remove-one-marker", "image": IMAGE,
                    "command": ["sh", "-ec", "test -f /fixture/marker && rm -- /fixture/marker && test ! -e /fixture/marker && printf 'marker-removed\\n'"],
                    "securityContext": {"allowPrivilegeEscalation": False,
                                        "capabilities": {"drop": ["ALL"]},
                                        "readOnlyRootFilesystem": True,
                                        "runAsNonRoot": True, "runAsUser": 65534},
                    "resources": {"requests": {"cpu": "5m", "memory": "8Mi"},
                                  "limits": {"cpu": "50m", "memory": "32Mi"}},
                    "volumeMounts": [{"name": "retained-fixture", "mountPath": "/fixture"}],
                }],
                "volumes": [{"name": "retained-fixture",
                             "persistentVolumeClaim": {"claimName": "saf-retained-volume-claim"}}],
            },
        },
    },
}
if action in {"delete", "dry-delete"}:
    method, path = "DELETE", PV
    body = {"apiVersion": "v1", "kind": "DeleteOptions"}
    if action == "dry-delete":
        body["dryRun"] = ["All"]
    content_type = "application/json"
elif action in {"wipe-dry-run", "wipe-create"}:
    method, path = "POST", JOBS + ("?dryRun=All" if action == "wipe-dry-run" else "")
    body, content_type = JOB_OBJECT, "application/json"
elif action in {"job-delete", "pvc-delete"}:
    method, path = "DELETE", JOB if action == "job-delete" else PVC
    body, content_type = {"apiVersion": "v1", "kind": "DeleteOptions"}, "application/json"
    body["propagationPolicy"] = "Background"
elif action in {"security-vote", "data-vote", "check-other-vote"}:
    method, path = "PATCH", LEDGER
    key = "security" if action == "security-vote" else "dataOwner"
    body = {"data": {key: "approved"}}
    if action == "check-other-vote":
        path += "?dryRun=All"
    content_type = "application/merge-patch+json"
else:
    raise SystemExit("invalid fixture action")

ca = ssl.create_default_context(cafile=str(MOUNT / "ca.crt"))
connection = HTTPSConnection("kubernetes.default.svc", timeout=8, context=ca)
headers = {"Authorization": "Bearer " + (MOUNT / "token").read_text().strip(),
           "Content-Type": content_type}
try:
    connection.request(method, path, body=json.dumps(body), headers=headers)
    response = connection.getresponse()
    data = json.load(response)
    print(json.dumps({"code": response.status, "reason": data.get("reason"), "detail": data.get("message") or ""}))
finally:
    connection.close()
