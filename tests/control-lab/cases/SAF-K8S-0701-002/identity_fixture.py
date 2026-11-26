"""Compare narrow fixture identity permissions with storage privilege queries."""
import json
import time

from fixtures import pod


NAMESPACE = "saf-test"
SERVICE_ACCOUNT = "saf-0701-002-reviewer"
POD = "saf-0701-002-owner"
IMAGE = "docker.io/library/python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89"
SCOPE = (
    "One fresh kind Kubernetes v1.36.1 cluster. A named synthetic ServiceAccount "
    "owns the fixture Pod and receives only named get access to one synthetic Pod "
    "and ConfigMap plus create on SelfSubjectAccessReview. The Pod submits its own "
    "read-only authorization queries using its projected token. It compares those "
    "permitted requests with StorageClass and CSI snapshot resource queries. No CSI "
    "driver, cloud provider, snapshot controller, or sensitive volume is installed."
)


def _resource(api_version, kind, name, **extra):
    return {"apiVersion": api_version, "kind": kind,
            "metadata": {"name": name, "namespace": NAMESPACE}, **extra}


def _script():
    # Use the Pod's real projected token and cluster CA; never print credential bytes.
    return '''import json, os, ssl, urllib.request

token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
token = open(token_path, encoding="utf-8").read().strip()
api = "https://%s:%s" % (os.environ["KUBERNETES_SERVICE_HOST"],
                           os.environ["KUBERNETES_SERVICE_PORT_HTTPS"])
context = ssl.create_default_context(cafile=ca_path)
identity_request = urllib.request.Request(
    api + "/apis/authentication.k8s.io/v1/selfsubjectreviews",
    data=json.dumps({"apiVersion": "authentication.k8s.io/v1",
                     "kind": "SelfSubjectReview"}).encode(),
    headers={"Authorization": "Bearer " + token,
             "Content-Type": "application/json"}, method="POST")
with urllib.request.urlopen(identity_request, context=context, timeout=20) as response:
    username = json.load(response)["status"]["userInfo"]["username"]
print("identity", username)
checks = [
    ("named-pod", "", "pods", "get", "saf-0701-002-owner", "saf-test"),
    ("named-configmap", "", "configmaps", "get", "saf-0701-002-public", "saf-test"),
    ("storageclass-create", "storage.k8s.io", "storageclasses", "create", "", ""),
    ("snapshot-class", "snapshot.storage.k8s.io", "volumesnapshotclasses", "list", "", ""),
    ("snapshot-content", "snapshot.storage.k8s.io", "volumesnapshotcontents", "list", "", ""),
    ("snapshot-create", "snapshot.storage.k8s.io", "volumesnapshots", "create", "", "saf-test"),
    ("snapshot-delete", "snapshot.storage.k8s.io", "volumesnapshots", "delete", "saf-fixture", "saf-test"),
]
for label, group, resource, verb, name, namespace in checks:
    attrs = {"group": group, "resource": resource, "verb": verb}
    if name:
        attrs["name"] = name
    if namespace:
        attrs["namespace"] = namespace
    body = json.dumps({"apiVersion": "authorization.k8s.io/v1",
                       "kind": "SelfSubjectAccessReview",
                       "spec": {"resourceAttributes": attrs}}).encode()
    request = urllib.request.Request(
        api + "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", data=body,
        headers={"Authorization": "Bearer " + token,
                 "Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, context=context, timeout=20) as response:
        status = json.load(response)["status"]
        allowed = None if status.get("evaluationError") else status.get("allowed")
    print(label, "allowed" if allowed is True else "denied" if allowed is False else "inconclusive")
'''


def run(lab):
    lab.create(_resource("v1", "ServiceAccount", SERVICE_ACCOUNT))
    review_role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
        "metadata": {"name": "saf-0701-002-self-review"},
        "rules": [
            {"apiGroups": ["authorization.k8s.io"],
             "resources": ["selfsubjectaccessreviews"], "verbs": ["create"]},
            {"apiGroups": ["authentication.k8s.io"],
             "resources": ["selfsubjectreviews"], "verbs": ["create"]},
        ],
    }
    lab.create(review_role)
    review_binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
        "metadata": {"name": "saf-0701-002-self-review"},
        "subjects": [{"kind": "ServiceAccount", "name": SERVICE_ACCOUNT,
                      "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                    "name": "saf-0701-002-self-review"},
    }
    lab.create(review_binding)
    lab.create(_resource("v1", "ConfigMap", "saf-0701-002-public",
                         data={"classification": "synthetic-public"}))
    configmap = {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": "saf-0701-002-probe", "namespace": NAMESPACE},
                 "data": {"probe.py": _script()}}
    lab.create(configmap)
    fixture = pod(POD, [{
        "name": "reviewer", "image": IMAGE,
        "command": ["python3", "-c", "import time; time.sleep(3600)"],
        "securityContext": {"allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True,
                            "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
        "volumeMounts": [{"name": "probe", "mountPath": "/fixture", "readOnly": True}],
    }], serviceAccountName=SERVICE_ACCOUNT, automountServiceAccountToken=True,
        volumes=[{"name": "probe", "configMap": {"name": "saf-0701-002-probe"}}])
    lab.create(fixture)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        state = lab.kubectl("get", "pod", POD, "-o", "json").stdout
        item = json.loads(state)
        if item.get("status", {}).get("phase") == "Running":
            break
        time.sleep(1)
    else:
        lab.block("The fixture Pod did not become ready to submit authorization review queries")

    def query():
        output = lab.kubectl("exec", POD, "-c", "reviewer", "--", "python3", "/fixture/probe.py")
        lines = [line.split() for line in output.stdout.splitlines()]
        identity = next((line[1] for line in lines if len(line) == 2 and line[0] == "identity"), None)
        decisions = {line[0]: line[1] for line in lines
                     if len(line) == 2 and line[0] != "identity"}
        return identity, decisions

    identity, baseline = query()
    lab.check("positive", "The API server authenticates the Pod's projected token as its named synthetic ServiceAccount",
              identity == f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT}",
              {"identity_matches_fixture_service_account":
               identity == f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT}"})
    no_access = {name: "denied" for name in (
        "named-pod", "named-configmap", "storageclass-create", "snapshot-class",
        "snapshot-content", "snapshot-create", "snapshot-delete")}
    lab.check("red", "Before the namespaced read-only RoleBinding, the same identity has no fixture or storage access",
              baseline == no_access,
              {"all_queries_denied": baseline == no_access, "query_count": len(baseline)})

    role = _resource("rbac.authorization.k8s.io/v1", "Role", "saf-0701-002-readonly")
    role["rules"] = [
        {"apiGroups": [""], "resources": ["pods"], "resourceNames": [POD], "verbs": ["get"]},
        {"apiGroups": [""], "resources": ["configmaps"],
         "resourceNames": ["saf-0701-002-public"], "verbs": ["get"]},
    ]
    lab.create(role)
    binding = _resource("rbac.authorization.k8s.io/v1", "RoleBinding", "saf-0701-002-readonly")
    binding["subjects"] = [{"kind": "ServiceAccount", "name": SERVICE_ACCOUNT, "namespace": NAMESPACE}]
    binding["roleRef"] = {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                          "name": "saf-0701-002-readonly"}
    lab.create(binding)
    expected = {
        "named-pod": "allowed", "named-configmap": "allowed", "storageclass-create": "denied",
        "snapshot-class": "denied", "snapshot-content": "denied",
        "snapshot-create": "denied", "snapshot-delete": "denied",
    }
    deadline = time.monotonic() + 20
    while True:
        green_identity, observed = query()
        if observed == expected or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("green", "The owning Pod's projected identity gains only the two named reads; storage queries remain denied",
              green_identity == identity and observed == expected,
              {"decisions": observed, "review_count": len(observed)})
