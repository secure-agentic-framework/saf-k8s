"""Verify a narrowly scoped monitoring identity against a disposable kubelet."""
import re
import subprocess
import time

from lab import NAMESPACE


SCOPE = (
    "Direct kubelet HTTPS on one owned Kubernetes v1.36.1 kind node. Test no "
    "credential, an authenticated service account without grants, and the same "
    "identity with node-specific health, statistics and metrics permissions. "
    "Provider-managed node settings and managed network controls require separate evidence."
)
ACCOUNT = "kubelet-metrics-reader"
NODE_ENDPOINTS = {
    "/healthz": "healthz",
    "/metrics": "metrics",
    "/stats/summary": "stats",
}


def mint_token(lab):
    # Lab.command retains stdout. Use an isolated call so only the process
    # handling the probe sees the credential and all reports contain statuses.
    result = subprocess.run(
        [
            "kubectl", "--kubeconfig", str(lab.kubeconfig),
            "--context", f"kind-{lab.cluster}", "-n", NAMESPACE,
            "--request-timeout=8s", "create", "token", ACCOUNT, "--duration=10m",
        ],
        env=lab.env, capture_output=True, text=True, timeout=15,
    )
    token = result.stdout.strip()
    if result.returncode or not re.fullmatch(r"[\w-]+\.[\w-]+\.[\w-]+", token, re.ASCII):
        lab.block("TokenRequest did not return a credential for the isolated monitor")
    return token


def kubelet_status(lab, path, token=None):
    node = f"{lab.cluster}-control-plane"
    curl_config = f'header = "Authorization: Bearer {token}"\n' if token else ""
    # The loopback address is inside the case-owned node. Its serving TLS
    # identity and network exposure are separate controls.
    result = subprocess.run(
        [
            "docker", "exec", "-i", "--user=65534:65534", node,
            "/usr/bin/curl", "--config", "-", "--silent", "--show-error",
            "--insecure", "--noproxy", "*", "--max-time", "5", "--request", "GET",
            "--output", "/dev/null", "--write-out", "%{http_code}",
            f"https://127.0.0.1:10250{path}",
        ],
        input=curl_config, env=lab.env, capture_output=True, text=True, timeout=10,
    )
    if result.returncode or not re.fullmatch(r"[1-5][0-9][0-9]", result.stdout):
        lab.block(f"The isolated kubelet did not return an HTTP status for {path}")
    return int(result.stdout)


def review(lab, node, subresource):
    result = lab.create({
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SubjectAccessReview",
        "spec": {
            "user": f"system:serviceaccount:{NAMESPACE}:{ACCOUNT}",
            "groups": ["system:authenticated", "system:serviceaccounts",
                       f"system:serviceaccounts:{NAMESPACE}"],
            "resourceAttributes": {
                "verb": "get", "resource": "nodes", "name": node,
                "subresource": subresource,
            },
        },
    })["status"]
    if result.get("evaluationError"):
        lab.block("Kubelet endpoint authorization review could not evaluate the RBAC policy")
    return result["allowed"]


def grant_monitoring(lab, node):
    api = "rbac.authorization.k8s.io/v1"
    lab.create({
        "apiVersion": api, "kind": "ClusterRole", "metadata": {"name": ACCOUNT},
        "rules": [{
            "apiGroups": [""], "resources": [f"nodes/{part}" for part in NODE_ENDPOINTS.values()],
            "resourceNames": [node], "verbs": ["get"],
        }],
    })
    lab.create({
        "apiVersion": api, "kind": "ClusterRoleBinding", "metadata": {"name": ACCOUNT},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                    "name": ACCOUNT},
        "subjects": [{"kind": "ServiceAccount", "name": ACCOUNT, "namespace": NAMESPACE}],
    })


def run(lab):
    lab.kubectl("create", "serviceaccount", ACCOUNT)
    node = f"{lab.cluster}-control-plane"
    token = mint_token(lab)
    status = kubelet_status(lab, "/healthz")
    lab.check("red", "The kubelet rejects a request without a credential", status == 401, status)
    for path in NODE_ENDPOINTS:
        status = kubelet_status(lab, path, token)
        lab.check("red", f"An authenticated monitor without a grant is denied at {path}",
                  status == 403, status)

    grant_monitoring(lab, node)
    deadline = time.monotonic() + 45
    while True:
        statuses = {path: kubelet_status(lab, path, token) for path in NODE_ENDPOINTS}
        if all(value == 200 for value in statuses.values()) or time.monotonic() >= deadline:
            break
        time.sleep(1)
    for path, status in statuses.items():
        lab.check("positive", f"The monitor can read its approved {path} endpoint",
                  status == 200, status)

    status = kubelet_status(lab, "/configz", token)
    lab.check("green", "The same monitor cannot read the unused /configz endpoint",
              status == 403, status)
    for resource in ("proxy", "pods", "configz", "log"):
        allowed = review(lab, node, resource)
        lab.check("green", f"Authorization still denies nodes/{resource}", not allowed, allowed)
    allowed = review(lab, "unapproved-monitoring-node", "metrics")
    lab.check("green", "The metrics grant is restricted to its named node", not allowed, allowed)
