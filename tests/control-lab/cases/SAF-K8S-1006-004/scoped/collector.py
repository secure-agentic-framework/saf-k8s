"""Read-only, in-cluster Kubernetes API snapshotter for synthetic case fixtures."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.request


TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token").read_text().strip()
CA_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
NAMESPACE = os.environ["FIXTURE_NAMESPACE"]
POD_NAME = os.environ["FIXTURE_POD"]
POD_UID = os.environ["FIXTURE_POD_UID"]
OTHER_NAMESPACE = os.environ["OTHER_NAMESPACE"]
API = f"https://{os.environ['KUBERNETES_SERVICE_HOST']}:{os.environ['KUBERNETES_SERVICE_PORT_HTTPS']}"
CONTEXT = ssl.create_default_context(cafile=CA_FILE)


def request(path):
    req = urllib.request.Request(API + path, headers={"Authorization": "Bearer " + TOKEN})
    with urllib.request.urlopen(req, context=CONTEXT, timeout=8) as response:
        return json.load(response)


def denied(path):
    req = urllib.request.Request(API + path, headers={"Authorization": "Bearer " + TOKEN})
    try:
        with urllib.request.urlopen(req, context=CONTEXT, timeout=8) as response:
            return {"status": response.status, "unexpected_success": True}
    except urllib.error.HTTPError as error:
        # Preserve only the status and API reason; never copy headers or credentials.
        try:
            body = json.loads(error.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            body = {}
        return {"status": error.code, "reason": body.get("reason", "")}


def source_object(obj, *, include_spec):
    metadata = obj.get("metadata", {})
    result = {
        "apiVersion": obj.get("apiVersion"),
        "kind": obj.get("kind"),
        "metadata": {key: metadata[key] for key in (
            "name", "namespace", "uid", "resourceVersion", "creationTimestamp", "labels"
        ) if key in metadata},
    }
    if include_spec:
        for field in ("subjects", "roleRef", "spec"):
            if field in obj:
                result[field] = obj[field]
    return result


binding_path = f"/apis/rbac.authorization.k8s.io/v1/namespaces/{NAMESPACE}/rolebindings"
policy_path = f"/apis/networking.k8s.io/v1/namespaces/{NAMESPACE}/networkpolicies"
namespace_path = f"/api/v1/namespaces/{NAMESPACE}"
version_path = "/version"

version = request(version_path)
namespace = request(namespace_path)
bindings = request(binding_path)
policies = request(policy_path)
other_namespace_check = denied(f"/api/v1/namespaces/{OTHER_NAMESPACE}")
label_prefix = "saf.example/"
psa_prefix = "pod-security.kubernetes.io/"
labels = namespace.get("metadata", {}).get("labels", {})
selected_labels = {key: value for key, value in sorted(labels.items())
                   if key.startswith(psa_prefix) or key.startswith(label_prefix)}
selected_bindings = [source_object(item, include_spec=True) for item in bindings.get("items", [])
                     if item.get("metadata", {}).get("labels", {}).get("saf.example/control-id") == "SAF-K8S-1006-004"
                     and "saf.example/fixture" in item.get("metadata", {}).get("labels", {})]
selected_policies = [source_object(item, include_spec=True) for item in policies.get("items", [])
                     if item.get("metadata", {}).get("labels", {}).get("saf.example/control-id") == "SAF-K8S-1006-004"]

capture = {
    "schema": "saf.example/kubernetes-capture/v1",
    "control_id": "SAF-K8S-1006-004",
    "provenance": {
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "cluster_git_version": version.get("gitVersion"),
        "namespace": NAMESPACE,
        "namespace_uid": namespace.get("metadata", {}).get("uid"),
        "namespace_resource_version": namespace.get("metadata", {}).get("resourceVersion"),
        "collector_service_account": f"system:serviceaccount:{NAMESPACE}:capture-reader",
        "collector_pod": POD_NAME,
        "collector_pod_uid": POD_UID,
        "api_get_paths": [version_path, namespace_path, binding_path, policy_path],
        "cross_namespace_namespace_get": other_namespace_check,
    },
    "namespace_pod_security_and_case_labels": selected_labels,
    "role_bindings": sorted(selected_bindings, key=lambda item: item["metadata"]["name"]),
    "network_policies": sorted(selected_policies, key=lambda item: item["metadata"]["name"]),
}
canonical = json.dumps(capture, sort_keys=True, separators=(",", ":")).encode("utf-8")
capture["provenance"]["content_sha256"] = hashlib.sha256(canonical).hexdigest()
print(json.dumps(capture, sort_keys=True, separators=(",", ":")), flush=True)
