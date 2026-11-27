"""Verify an excluded endpoint and a separate approved workload identity."""

import json
from pathlib import Path
import time

SCOPE = "Local Pod egress and genuine Kubernetes projected identity against owned cluster endpoints."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
CLIENT = '''import json, sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
request = Request('http://' + sys.argv[1] + ':8080/marker')
if sys.argv[2] == 'identity':
    request.add_header('Authorization', 'Bearer ' + Path('/identity/token').read_text().strip())
try:
    with urlopen(request, timeout=2) as reply:
        print(json.dumps({'code': reply.status, 'marker': reply.read().decode()}))
except HTTPError as error:
    print(json.dumps({'code': error.code}))
except (TimeoutError, URLError) as error:
    if isinstance(error, TimeoutError) or isinstance(getattr(error, 'reason', None), TimeoutError):
        print(json.dumps({'code': 'timeout'}))
    else:
        raise
'''


def add_pod(lab, name, mode, account, *, projected=()):
    server = mode != "client"
    command = ["python", "/fixture/marker.py"] if server else ["python", "-c", "import time; time.sleep(220)"]
    volumes = [{"name": "program", "configMap": {"name": "fixture-markers"}}]
    mounts = [{"name": "program", "mountPath": "/fixture", "readOnly": True}]
    if projected:
        volumes.append({"name": "identity", "projected": {"sources": list(projected)}})
        mounts.append({"name": "identity", "mountPath": "/identity", "readOnly": True})
    readiness = {"readinessProbe": {"httpGet": {"path": "/health", "port": 8080}, "periodSeconds": 1}} if server else {}
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {"app": name}},
                "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False, "serviceAccountName": account,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                         "volumes": volumes, "containers": [{"name": "marker", "image": IMAGE, "command": command,
                             "env": [{"name": "MODE", "value": mode}], "volumeMounts": mounts, **readiness,
                             "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"cpu": "150m", "memory": "64Mi"}},
                             "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                 "capabilities": {"drop": ["ALL"]}}}]}})
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=60s", timeout=70)
    return json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)["status"]["podIP"]


def fetch(lab, ip, *, identity=False):
    result = lab.kubectl("exec", "fixture-probe", "--", "python", "-c", CLIENT, ip,
                          "identity" if identity else "none", timeout=15)
    return json.loads(result.stdout)


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "fixture-markers"}, "immutable": True,
                "data": {"marker.py": Path(__file__).with_name("marker.py").read_text()}})
    for account in ("fixture-marker-client", "fixture-marker-reviewer"):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": account}, "automountServiceAccountToken": False})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "fixture-marker-review"},
                "rules": [{"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "fixture-marker-review"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "fixture-marker-review"},
                "subjects": [{"kind": "ServiceAccount", "namespace": "saf-test", "name": "fixture-marker-reviewer"}]})
    review_sources = ({"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
                      {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}})
    selected = add_pod(lab, "fixture-identity", "identity", "fixture-marker-reviewer", projected=review_sources)
    comparison = add_pod(lab, "fixture-comparison", "comparison", "default")
    add_pod(lab, "fixture-probe", "client", "fixture-marker-client",
            projected=({"serviceAccountToken": {"path": "token", "audience": "saf-fixture-marker", "expirationSeconds": 600}},))
    baseline = fetch(lab, comparison)
    lab.check("red", "The excluded endpoint is healthy and reachable before fixture egress policy",
              baseline == {"code": 200, "marker": "public-comparison-marker"}, {"comparison_marker_reached": baseline.get("code") == 200})
    lab.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "allow-fixture-identity"},
                "spec": {"podSelector": {"matchLabels": {"app": "fixture-probe"}}, "policyTypes": ["Egress"],
                         "egress": [{"to": [{"podSelector": {"matchLabels": {"app": "fixture-identity"}}}],
                                     "ports": [{"protocol": "TCP", "port": 8080}]}]}})
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        if fetch(lab, comparison) == {"code": "timeout"}:
            break
        time.sleep(1)
    else:
        lab.block("Fixture egress policy did not prevent the comparison connection")
    unauthenticated = fetch(lab, selected) == {"code": 401}
    lab.check("green", "The omitted path is denied, and the reachable approved endpoint still requires identity",
              unauthenticated, {"omitted_path_denied": True, "allowed_endpoint_requires_authentication": unauthenticated})
    accepted = fetch(lab, selected, identity=True) == {"code": 200, "marker": "public-identity-marker"}
    lab.check("positive", "An audience-bound Kubernetes ServiceAccount token permits the approved fixture request",
              accepted, {"projected_identity_and_marker_verified": accepted})
    (lab.evidence / "metadata-egress-observations.json").write_text(json.dumps({"comparison_pre_policy_reachable": True,
        "comparison_post_policy_denied": True, "approved_rejects_missing_identity": unauthenticated,
        "approved_accepts_workload_identity": accepted, "fixture_endpoints_only": True}, indent=2) + "\n")
