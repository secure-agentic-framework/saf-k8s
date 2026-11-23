"""Validate isolated model versions and policy-controlled weighted routing."""
import json
from pathlib import Path
import time

from fixtures import container

HERE = Path(__file__).parent
NS = "saf-test"
STABLE = "saf-model-stable"
CANDIDATE = "saf-model-candidate"
IMAGE = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
SCOPE = (
    "A fresh Kind v1.36.1 cluster with bundled kindnet. Separate stable and candidate workloads "
    "serve inert version markers from different namespaces. A fixture router reads an approved "
    "ConfigMap and routes a fixed request cohort. RBAC constrains policy changes and a native "
    "NetworkPolicy isolates the stable destination from direct requests by the candidate. "
    "The stable Service continues serving when the candidate is absent. Gateway API, service "
    "mesh behavior, production routing and availability, full resource isolation and GPU or MIG "
    "separation remain open."
)


def _create(lab, ns, resource):
    return json.loads(lab.kubectl("-n", ns, "create", "-f", "-", "-o", "json", payload=json.dumps(resource)).stdout)


def _role(lab, identity, verbs):
    api = "rbac.authorization.k8s.io/v1"
    lab.create({"apiVersion": api, "kind": "Role", "metadata": {"name": identity},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["route-policy"],
                           "verbs": verbs}]})
    lab.create({"apiVersion": api, "kind": "RoleBinding", "metadata": {"name": identity},
                "subjects": [{"kind": "ServiceAccount", "name": identity, "namespace": NS}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": identity}})


def _model(lab, ns, role, *, sa="default", replicas=1):
    name = "router" if role == "route" else "model"
    labels = {"app": name}
    code = (HERE / "serve.py").read_text()
    _create(lab, ns, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "serve-code"},
                      "immutable": True, "data": {"serve.py": code}})
    app = container("app", image=IMAGE, command=["python", "-B", "/app/serve.py"],
                    ports=[{"containerPort": 8080}],
                    readinessProbe={"httpGet": {"path": "/health", "port": 8080}, "periodSeconds": 1},
                    env=[{"name": "MODE", "value": role}],
                    volumeMounts=[{"name": "code", "mountPath": "/app", "readOnly": True}],
                    resources={"requests": {"cpu": "10m", "memory": "24Mi"},
                               "limits": {"cpu": "150m", "memory": "64Mi"}})
    _create(lab, ns, {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
                      "spec": {"replicas": replicas, "selector": {"matchLabels": labels},
                               "template": {"metadata": {"labels": labels},
                                            "spec": {"serviceAccountName": sa,
                                                     "automountServiceAccountToken": role == "route",
                                                     "terminationGracePeriodSeconds": 1,
                                                     "containers": [app], "volumes": [
                                                         {"name": "code", "configMap": {"name": "serve-code"}}]}}}})
    _create(lab, ns, {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                      "spec": {"selector": labels, "ports": [{"port": 8080, "targetPort": 8080}]}})


def _ready(lab, ns, name):
    lab.kubectl("-n", ns, "rollout", "status", "deployment/" + name, "--timeout=70s", timeout=75)


def _scale(lab, replicas):
    lab.kubectl("-n", CANDIDATE, "scale", "deployment/model", f"--replicas={replicas}")


def _count(lab):
    # Cohort spans the full allocation range using 20 fixed IDs.
    client = """from collections import Counter
import json
from urllib.request import urlopen
rows = []
for n in range(0,100,5):
    with urlopen('http://router:8080/model?id='+str(n), timeout=3) as response:
        rows.append(response.read().decode())
print(json.dumps(dict(Counter(rows))))"""
    return json.loads(lab.kubectl("exec", "deployment/router", "--", "python", "-B", "-c", client,
                                   timeout=45).stdout)


def _direct(lab):
    client = """import json,socket
from urllib.error import URLError
from urllib.request import urlopen
try:
    with urlopen('http://model.saf-model-stable.svc:8080/model',timeout=2) as response:
        print(json.dumps({'outcome':'served','body':response.read().decode()}))
except (TimeoutError,socket.timeout):
    print(json.dumps({'outcome':'timeout'}))
except URLError as exc:
    if isinstance(exc.reason, (TimeoutError,socket.timeout)):
        print(json.dumps({'outcome':'timeout'}))
    else:
        raise"""
    return json.loads(lab.kubectl("-n", CANDIDATE, "exec", "deployment/model", "--",
                                   "python", "-B", "-c", client, timeout=10).stdout)


def _set_weight(lab, value, identity):
    return lab.kubectl("patch", "configmap/route-policy", "--type=merge",
                       "-p", json.dumps({"data": {"candidatePercent": str(value)}}),
                       "--as=system:serviceaccount:" + identity, allow_failure=True)


def run(lab):
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=65)
    for ns in (STABLE, CANDIDATE):
        lab.kubectl("create", "namespace", ns)
    for identity, namespace in (("router", NS), ("route-approver", NS), ("model", CANDIDATE)):
        _create(lab, namespace, {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": identity}})
    _role(lab, "router", ["get"])
    _role(lab, "route-approver", ["get", "patch"])
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "route-policy"},
                "data": {"candidatePercent": "0"}})
    _model(lab, STABLE, "stable")
    _model(lab, CANDIDATE, "candidate", sa="model", replicas=0)
    _model(lab, NS, "route", sa="router")
    _ready(lab, STABLE, "model")
    _ready(lab, NS, "router")
    stable_only = _count(lab)
    lab.check("positive", "Stable serves the entire fixed cohort with the candidate absent",
              stable_only == {"stable": 20}, stable_only)

    _scale(lab, 1)
    _ready(lab, CANDIDATE, "model")
    plain = _direct(lab)
    lab.check("red", "Without ingress isolation the running candidate can reach stable",
              plain == {"outcome": "served", "body": "stable"}, plain)
    authorized = _set_weight(lab, 20, NS + ":route-approver")
    if authorized.returncode:
        lab.block("The separate route approver did not update the intended policy")
    denied = _set_weight(lab, 40, CANDIDATE + ":model")
    permission = lab.kubectl("auth", "can-i", "patch", "configmap/route-policy",
                             "--as=system:serviceaccount:" + CANDIDATE + ":model", allow_failure=True).stdout.strip()
    measured = _count(lab)
    lab.check("green", "The candidate identity cannot change the approved route weight and the live split stays 80/20",
              denied.returncode != 0 and "forbidden" in denied.stderr.lower()
              and permission == "no" and measured == {"stable": 16, "candidate": 4},
              {"candidate_policy_change_forbidden": "forbidden" in denied.stderr.lower(), "counts": measured})
    _create(lab, STABLE, {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                         "metadata": {"name": "only-route-enters-stable"},
                         "spec": {"podSelector": {"matchLabels": {"app": "model"}}, "policyTypes": ["Ingress"],
                                  "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {
                                      "kubernetes.io/metadata.name": NS}},
                                      "podSelector": {"matchLabels": {"app": "router"}}}],
                                               "ports": [{"protocol": "TCP", "port": 8080}]}]}})
    deadline = time.monotonic() + 24
    while True:
        isolated = _direct(lab)
        if isolated == {"outcome": "timeout"} or time.monotonic() >= deadline:
            break
        time.sleep(0.35)
    after = _count(lab)
    lab.check("green", "Network isolation denies the same direct candidate route while the approved split still serves",
              isolated == {"outcome": "timeout"} and after == measured,
              {"direct_candidate_probe": isolated["outcome"], "counts": after})
    if _set_weight(lab, 0, NS + ":route-approver").returncode:
        lab.block("The authorized route approver could not restore stable-only routing")
    _scale(lab, 0)
    result = _count(lab)
    lab.check("positive", "The stable route continues to serve after withdrawing the candidate",
              result == {"stable": 20}, result)
    (lab.evidence / "canary-isolation.json").write_text(json.dumps(
        {"before_candidate": stable_only, "version_split": measured, "after_isolation": after,
         "after_withdrawal": result, "checks": lab.checks}, indent=2) + "\n")
