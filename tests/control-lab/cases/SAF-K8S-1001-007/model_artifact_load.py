"""Read one inert model-artifact descriptor and emit a scoped Kubernetes API receipt."""
import hashlib
import json
import os
from pathlib import Path
import ssl
import urllib.request


artifact_bytes = Path("/model/artifact.json").read_bytes()
artifact = json.loads(artifact_bytes)
if (set(artifact) != {"model", "version", "format", "fixture_only"}
        or artifact.get("fixture_only") is not True
        or artifact.get("format") != "metadata-only-json-marker"):
    raise SystemExit("fixture artifact schema rejected")

artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
namespace = os.environ["POD_NAMESPACE"]
pod_name = os.environ["POD_NAME"]
pod_uid = os.environ["POD_UID"]
service_account = os.environ["POD_SERVICE_ACCOUNT"]
event_id = "saf-k8s-1001-007-load-" + hashlib.sha256(
    f"{pod_uid}:{artifact_sha256}".encode()).hexdigest()
event = {
    "event_id": event_id,
    "event_type": "model_artifact_loaded",
    "model": artifact["model"],
    "version": artifact["version"],
    "artifact_name": "artifact.json",
    "artifact_sha256": artifact_sha256,
    "namespace": namespace,
    "pod_name": pod_name,
    "pod_uid": pod_uid,
    "service_account": f"system:serviceaccount:{namespace}:{service_account}",
}

host = os.environ["KUBERNETES_SERVICE_HOST"]
port = os.environ["KUBERNETES_SERVICE_PORT"]
receipt_name = "model-load-receipt"
url = (f"https://{host}:{port}/api/v1/namespaces/{namespace}/configmaps/"
       f"{receipt_name}")
token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token").read_text().strip()
context = ssl.create_default_context(cafile="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
payload = json.dumps({"data": {"event.json": json.dumps(event, sort_keys=True,
                                                       separators=(",", ":"))}},
                     separators=(",", ":")).encode()
request = urllib.request.Request(
    url, data=payload,
    headers={"Authorization": "Bearer " + token,
             "Content-Type": "application/merge-patch+json"},
    method="PATCH",
)
with urllib.request.urlopen(request, context=context, timeout=8) as response:
    patched = response.status == 200
print(json.dumps({"event_id": event_id, "pod_uid": pod_uid,
                  "artifact_sha256": artifact_sha256,
                  "receipt_patched": patched}, sort_keys=True))
if not patched:
    raise SystemExit(1)
