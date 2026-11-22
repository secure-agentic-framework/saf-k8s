"""Synthetic API authorization/admission checks; never prints bearer credentials."""
import json
import ssl
import sys
import urllib.error
import urllib.request


NAMESPACE = "saf-0901-006"
API = "https://kubernetes.default.svc"
TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
POD_PATH = f"/api/v1/namespaces/{NAMESPACE}/pods"
QUOTA_PATH = f"/api/v1/namespaces/{NAMESPACE}/resourcequotas"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)


def pod(name, cpu, memory):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/fixture": "synthetic-only"}},
        "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                 "containers": [{
                     "name": "mock-workload", "image": IMAGE,
                     "command": ["python", "-c", "import time; time.sleep(3600)"],
                     "resources": {"requests": {"cpu": cpu, "memory": memory}},
                     "securityContext": {"allowPrivilegeEscalation": False,
                                          "capabilities": {"drop": ["ALL"]},
                                          "runAsNonRoot": True, "runAsUser": 65534,
                                          "readOnlyRootFilesystem": True,
                                          "seccompProfile": {"type": "RuntimeDefault"}},
                 }]},
    }


def quota(name):
    return {
        "apiVersion": "v1", "kind": "ResourceQuota",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "annotations": {"saf-k8s.example/fixture": "synthetic-only"}},
        "spec": {"hard": {"pods": "4", "requests.cpu": "2", "requests.memory": "1Gi"}},
    }


def request(method, path, body=None):
    token = open(TOKEN_PATH, encoding="utf-8").read().strip()
    context = ssl.create_default_context(cafile=CA_PATH)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        API + path, data=data, method=method,
        headers={"Authorization": "Bearer " + token,
                 "Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, context=context, timeout=10) as response:
            status = response.status
            raw = response.read()
    except urllib.error.HTTPError as error:
        status = error.code
        raw = error.read()
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        obj = {}
    metadata = obj.get("metadata", {})
    result = {"status": status, "reason": obj.get("reason"),
              "message": obj.get("message", "")}
    if metadata.get("name"):
        result["name"] = metadata["name"]
    return result


operation = sys.argv[1]
if operation == "baseline-pod":
    result = request("POST", POD_PATH,
                     pod("saf-0901-006-baseline", "600m", "128Mi"))
elif operation == "over-quota-pod":
    result = request("POST", POD_PATH,
                     pod("saf-0901-006-over-quota", "600m", "128Mi"))
elif operation == "small-pod":
    result = request("POST", POD_PATH,
                     pod("saf-0901-006-small", "100m", "64Mi"))
elif operation == "tenant-create-quota":
    result = request("POST", QUOTA_PATH + "?dryRun=All", quota("saf-0901-006-tenant-probe"))
elif operation == "platform-dry-run-create-quota":
    result = request("POST", QUOTA_PATH + "?dryRun=All", quota("saf-0901-006-admin-probe"))
else:
    raise SystemExit("unknown synthetic probe operation")

print(json.dumps(result, sort_keys=True))
