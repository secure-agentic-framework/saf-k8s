"""Audit and verify a namespace-scoped workload identity."""
import json
from pathlib import Path
import time

from fixtures import container, pod

PROBE = Path(__file__).with_name("probe.py").read_text()
TENANT = "saf-0702-024-enrolled"
OTHER = "saf-0702-024-synthetic"
RECORD = "tenant-record"
SERVICE_ACCOUNT = "tenant-workload"
ROLE = "saf-0702-024-read-one-configmap"
BINDING = "saf-0702-024-tenant-workload"
MARKER = "tenant-namespace-synthetic-marker"
API_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
SCOPE = (
    "A v1.36.1 kind administrator inventories direct RoleBinding and ClusterRoleBinding "
    "subjects for one synthetic ServiceAccount. The inventory finds planted cross-namespace "
    "and cluster-wide reads of only a named fixture and confirms removal. A nonroot Pod uses "
    "its genuine identity for a permitted tenant-local read and self-access reviews. The "
    "case leaves group grants, other principals, exception governance, and deployed audit "
    "cadence for independent evidence."
)


def namespaced(name, namespace):
    metadata = {"name": name}
    if namespace:
        metadata["namespace"] = namespace
    return metadata


def create(lab, resource):
    namespace = resource["metadata"].get("namespace")
    context = ("-n", namespace) if namespace else ()
    lab.kubectl(*context, "create", "-f", "-", payload=json.dumps(resource))


def role(lab, namespace):
    create(lab, {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role" if namespace else "ClusterRole",
        "metadata": namespaced(ROLE, namespace),
        "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                   "resourceNames": [RECORD], "verbs": ["get"]}],
    })


def binding(lab, namespace):
    create(lab, {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding" if namespace else "ClusterRoleBinding",
        "metadata": namespaced(BINDING, namespace),
        "subjects": [{"kind": "ServiceAccount", "name": SERVICE_ACCOUNT, "namespace": TENANT}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role" if namespace else "ClusterRole", "name": ROLE},
    })


def direct_bindings(lab):
    roles = json.loads(lab.kubectl("get", "rolebindings", "-A", "-o", "json").stdout)["items"]
    cluster = json.loads(lab.kubectl("get", "clusterrolebindings", "-o", "json").stdout)["items"]
    matching = []
    for item in roles + cluster:
        metadata = item["metadata"]
        namespace = metadata.get("namespace")
        for subject in item.get("subjects", []):
            if (subject.get("kind") == "ServiceAccount" and subject.get("name") == SERVICE_ACCOUNT
                    and (subject.get("namespace") or namespace) == TENANT):
                matching.append(f"{namespace or 'cluster'}/{metadata['name']}")
                break
    return sorted(matching)


def in_pod(lab, mode, namespace):
    result = lab.kubectl("-n", TENANT, "exec", f"pod/{SERVICE_ACCOUNT}", "--",
                         "python", "-c", PROBE, mode, namespace, timeout=30)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        lab.block("The fixture Pod returned malformed authorization evidence")


def reviewed_allowed(lab, namespace):
    result = in_pod(lab, "review", namespace)
    if result.get("code") != 201 or result.get("evaluation_error") or type(result.get("allowed")) is not bool:
        lab.block(f"SelfSubjectAccessReview for {namespace} did not return an evaluated decision")
    return result["allowed"]


def run(lab):
    server = json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    if server != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {server!r}")

    for namespace, marker in ((TENANT, MARKER), (OTHER, "separate-namespace-synthetic-marker")):
        lab.kubectl("create", "namespace", namespace)
        create(lab, {
            "apiVersion": "v1", "kind": "ConfigMap", "metadata": namespaced(RECORD, namespace),
            "data": {"marker": marker},
        })
    lab.kubectl("-n", TENANT, "create", "serviceaccount", SERVICE_ACCOUNT)

    for namespace in (TENANT, OTHER, None):
        role(lab, namespace)
        binding(lab, namespace)
    matching = direct_bindings(lab)
    expected = sorted([f"{TENANT}/{BINDING}", f"{OTHER}/{BINDING}", f"cluster/{BINDING}"])
    lab.check("red", "The administrator inventory detects both planted grants outside the enrolled namespace",
              matching == expected, {"direct_bindings": matching})
    lab.kubectl("-n", OTHER, "delete", "rolebinding", BINDING)
    lab.kubectl("delete", "clusterrolebinding", BINDING)
    lab.kubectl("-n", TENANT, "delete", "rolebinding", BINDING)

    workload = pod(SERVICE_ACCOUNT, [container("probe", image=API_IMAGE)],
                   serviceAccountName=SERVICE_ACCOUNT, automountServiceAccountToken=True)
    workload["metadata"]["namespace"] = TENANT
    create(lab, workload)
    lab.kubectl("-n", TENANT, "wait", "--for=condition=Ready", f"pod/{SERVICE_ACCOUNT}",
                "--timeout=90s", timeout=100)
    before = reviewed_allowed(lab, TENANT)
    lab.check("red", "Before the tenant RoleBinding, the Pod's own access review denies its local read",
              before is False, {"allowed": before})

    binding(lab, TENANT)
    matching = direct_bindings(lab)
    lab.check("green", "Remediation leaves exactly the enrolled namespace binding",
              matching == [f"{TENANT}/{BINDING}"], {"direct_bindings": matching})

    deadline = time.monotonic() + 20
    while True:
        local_review = reviewed_allowed(lab, TENANT)
        if local_review or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    cross_review = reviewed_allowed(lab, OTHER)
    lab.check("green", "The named read in the separate workspace is denied by the Pod's own access review",
              cross_review is False, {"target_namespace": OTHER, "allowed": cross_review,
                                      "resource_request_sent": False})
    read = in_pod(lab, "read", TENANT)
    lab.check("positive", "The Pod can read its permitted local synthetic ConfigMap",
              local_review is True and read == {"code": 200, "marker": MARKER},
              {"target_namespace": TENANT, "local_access_review_allowed": local_review, "workload_get": read})
