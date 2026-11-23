"""Measure separate Pod network policy directions and a scoped API authorization boundary."""

import json
import time

SCOPE = "Owned TCP marker paths and Kubernetes API authorization on Kind. Cloud configuration requires provider evidence."
IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
SRC = "saf-flow-source"
DEST = "saf-flow-destination"
OTHER = "saf-flow-comparison"
PORT = 18080


def object_create(lab, namespace, resource):
    lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(resource))


def pod(lab, namespace, name, *, response=None):
    command = "exec sleep 240" if response is None else f"printf '%s' '{response}' > /tmp/index.html; exec httpd -f -p {PORT} -h /tmp"
    readiness = {"readinessProbe": {"httpGet": {"path": "/", "port": PORT}, "periodSeconds": 1}} if response else {}
    object_create(lab, namespace, {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
                  "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                           "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                           "containers": [{"name": "fixture", "image": IMAGE, "command": ["/bin/sh", "-ec", command], **readiness,
                                           "resources": {"requests": {"cpu": "5m", "memory": "4Mi"},
                                                         "limits": {"cpu": "100m", "memory": "30Mi"}},
                                           "securityContext": {"allowPrivilegeEscalation": False,
                                                               "capabilities": {"drop": ["ALL"]}}}]}})
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=60s", timeout=70)
    return json.loads(lab.kubectl("-n", namespace, "get", "pod", name, "-o", "json").stdout)["status"]["podIP"]


def policy(lab, namespace, name, direction, peers):
    direction_key = "from" if direction == "Ingress" else "to"
    rules = [{direction_key: [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": peers}}}],
              "ports": [{"protocol": "TCP", "port": PORT}]}] if peers else []
    object_create(lab, namespace, {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                  "metadata": {"name": name}, "spec": {"podSelector": {}, "policyTypes": [direction], direction.lower(): rules}})


def fetch(lab, namespace, ip, marker):
    trial = lab.kubectl("-n", namespace, "exec", "probe", "--", "wget", "-T", "2", "-O-", f"http://{ip}:{PORT}/",
                        timeout=12, allow_failure=True)
    if trial.returncode == 0:
        if trial.stdout.strip() != marker:
            lab.block("The fixture request returned the wrong marker")
        return True
    if "timed out" in trial.stderr.lower():
        return False
    lab.block("The fixture request failed for a reason other than the expected policy timeout")


def await_result(lab, check, message):
    ends = time.monotonic() + 30
    while time.monotonic() < ends:
        if check():
            return
        time.sleep(1)
    lab.block(message)


def api_boundary(lab):
    for subject in ("flow-reader", "flow-other"):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": subject},
                    "automountServiceAccountToken": False})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "network-api-marker"},
                "data": {"marker": "public-api-fixture"}})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "flow-api-read"},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["network-api-marker"], "verbs": ["get"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "flow-api-read"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "flow-api-read"},
                "subjects": [{"kind": "ServiceAccount", "name": "flow-reader", "namespace": "saf-test"}]})
    allowed = lab.kubectl("--as", "system:serviceaccount:saf-test:flow-reader", "get", "configmap", "network-api-marker", "-o", "json",
                          allow_failure=True)
    denied = lab.kubectl("--as", "system:serviceaccount:saf-test:flow-other", "get", "configmap", "network-api-marker", "-o", "json",
                         allow_failure=True)
    return (allowed.returncode == 0 and json.loads(allowed.stdout)["data"]["marker"] == "public-api-fixture",
            denied.returncode != 0 and "Forbidden" in denied.stderr)


def run(lab):
    cni = json.loads(lab.kubectl("-n", "kube-system", "get", "daemonset", "kindnet", "-o", "json").stdout)
    image = cni["spec"]["template"]["spec"]["containers"][0]["image"]
    for name in (SRC, DEST, OTHER):
        lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": {
            "pod-security.kubernetes.io/enforce": "restricted"}}})
    pod(lab, SRC, "probe")
    pod(lab, OTHER, "probe")
    dest = pod(lab, DEST, "target", response="primary-public-marker")
    comparison = pod(lab, OTHER, "target", response="comparison-public-marker")
    to_primary = lambda source: fetch(lab, source, dest, "primary-public-marker")
    to_comparison = lambda: fetch(lab, SRC, comparison, "comparison-public-marker")
    await_result(lab, lambda: to_primary(SRC) and to_primary(OTHER) and to_comparison(), "Both fixture paths must be healthy before policy")
    lab.check("red", "Both fixture clients can reach the primary marker before policy",
              True, {"baseline_paths_verified": True})
    policy(lab, DEST, "own-ingress", "Ingress", SRC)
    await_result(lab, lambda: not to_primary(OTHER) and to_primary(SRC) and to_comparison(), "Ingress policy did not converge")
    lab.check("green", "Destination ingress allows the named source and denies the comparison source",
              True, {"allowlisted_source_reached_marker": True, "comparison_source_denied": True})
    policy(lab, SRC, "isolate-egress", "Egress", None)
    await_result(lab, lambda: not to_primary(SRC) and not to_comparison(), "Source egress policy did not converge")
    lab.check("green", "Source egress must also allow the path despite positive destination ingress",
              True, {"ingress_allow_insufficient_with_egress_denial": True})
    policy(lab, SRC, "allow-approved-destination", "Egress", DEST)
    await_result(lab, lambda: to_primary(SRC) and not to_comparison() and not to_primary(OTHER), "Final policy paths did not converge")
    allowed, denied = api_boundary(lab)
    lab.check("positive", "Both-direction allowance restores the selected path and the API applies its own scoped access",
              allowed and denied, {"only_approved_marker_returned": True, "api_reader_allowed": allowed, "other_api_reader_denied": denied})
    (lab.evidence / "network-boundary-observations.json").write_text(json.dumps({"cni_image": image,
        "pod_ingress_egress_independently_enforced": True, "api_authorization_allowed_and_denied": allowed and denied,
        "cloud_perimeter_status": "requires-deployed-provider-evidence"}, indent=2) + "\n")
