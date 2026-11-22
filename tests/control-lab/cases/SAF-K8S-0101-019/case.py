"""Review an explicit live authorization chain and a harmless policy record."""
import base64
import http.client
import ipaddress
import json
from pathlib import Path
import ssl
import subprocess
import time
from urllib.parse import urlsplit


HERE = Path(__file__).parent
NAMESPACE = "saf-test"
ACCOUNT = "saf-0101-019-reader"
ALLOWED = "saf-0101-019-allowed"
NEIGHBOR = "saf-0101-019-neighbor"
POLICY = "saf-0101-019-authorizer-chain"
DENIAL = "SAF-K8S-0101-019 approved fixture permits exactly Node,RBAC and prohibits AlwaysAllow"
SCOPE = (
    "Self-managed Kind Kubernetes v1.36.1 only. Inspect the runner-owned live "
    "kube-apiserver command for the explicit Node,RBAC authorization-mode chain; "
    "use a genuine case-owned ServiceAccount token to read one RBAC-named synthetic "
    "ConfigMap and confirm a neighboring synthetic ConfigMap is forbidden; and "
    "exercise a namespace and label scoped ValidatingAdmissionPolicy against "
    "server-side dry-run ConfigMap records containing inert authorizer-chain text. "
    "No proposed authorization configuration is applied to an API server. "
    "Managed-service settings and production chain approval require separate evidence."
)


def split_flag(command, name):
    values = []
    for i, arg in enumerate(command):
        if arg == name:
            values.append(command[i + 1] if i + 1 < len(command) else None)
        elif arg.startswith(name + "="):
            values.append(arg.split("=", 1)[1])
    return values


def live_chain(lab):
    version = json.loads(lab.kubectl("get", "--raw", "/version").stdout)
    if version.get("gitVersion") != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, observed {version.get('gitVersion')!r}")

    pod_name = f"kube-apiserver-{lab.cluster}-control-plane"
    pod = json.loads(lab.kubectl("-n", "kube-system", "get", f"pod/{pod_name}", "-o", "json").stdout)
    containers = [item for item in pod["spec"]["containers"] if item.get("name") == "kube-apiserver"]
    if len(containers) != 1:
        lab.block("Could not identify exactly one kube-apiserver container")
    command = containers[0].get("command", []) + containers[0].get("args", [])
    modes = split_flag(command, "--authorization-mode")
    configs = split_flag(command, "--authorization-config")
    if len(modes) != 1 or modes[0] is None or not modes[0].strip() or configs:
        lab.block("Expected exactly one explicit authorization-mode and no structured authorization-config")
    chain = [mode.strip() for mode in modes[0].split(",")]
    return chain


def policy_object():
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": NAMESPACE}},
                "objectSelector": {"matchLabels": {"saf-k8s.example/control": "0101-019"}},
                "resourceRules": [{
                    "apiGroups": [""], "apiVersions": ["v1"],
                    "operations": ["CREATE"], "resources": ["configmaps"],
                }],
            },
            "validations": [{
                "expression": (
                    "has(object.data) && has(object.data.authorizerChain) && "
                    "object.data.authorizerChain == 'Node,RBAC'"
                ),
                "message": DENIAL,
                "reason": "Forbidden",
            }],
        },
    }


def policy_binding():
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": POLICY},
        "spec": {"policyName": POLICY, "validationActions": ["Deny"]},
    }


def submit_record(lab, name, chain):
    record = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {"saf-k8s.example/control": "0101-019"},
        },
        "data": {"authorizerChain": chain},
    }
    return lab.kubectl(
        "create", "-f", "-", "-o", "json", "--dry-run=server",
        payload=json.dumps(record), allow_failure=True,
    )


def create_sa_token(lab):
    """Mint a short-lived token without writing its value to evidence or argv."""
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "-n", NAMESPACE, "create", "token", ACCOUNT, "--duration=10m"]
    with (lab.evidence / "commands.log").open("a") as log:
        log.write(f"$ kubectl --kubeconfig <runner-kubeconfig> --context kind-{lab.cluster} "
                  f"-n {NAMESPACE} create token {ACCOUNT} --duration=10m [token output redacted]\n")
        result = subprocess.run(args, text=True, capture_output=True, env=lab.env, timeout=30)
        log.write(f"[token output redacted; exit {result.returncode}]\n\n")
    if result.returncode:
        lab.block("Could not mint a short-lived token for the case-owned ServiceAccount")
    token = result.stdout.strip()
    if not token:
        lab.block("TokenRequest returned an empty ServiceAccount token")
    return token


def api_client_config(lab):
    """Read only endpoint and CA data; never retain or log admin credentials."""
    def field(name):
        args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                "config", "view", "--raw", "--minify", "-o", f"jsonpath={{.clusters[0].cluster.{name}}}"]
        result = subprocess.run(args, text=True, capture_output=True, env=lab.env, timeout=20)
        if result.returncode:
            lab.block("Could not read the case-owned endpoint field")
        return result.stdout.strip()
    server = urlsplit(field("server"))
    if server.scheme != "https" or not server.port or not ipaddress.ip_address(server.hostname).is_loopback:
        lab.block("Expected the owned API endpoint on HTTPS loopback")
    ca = base64.b64decode(field("certificate-authority-data"), validate=True)
    context = ssl.create_default_context(cadata=ca.decode("ascii"))
    return server, context


def service_account_get(lab, token, server, tls, name):
    path = f"/api/v1/namespaces/{NAMESPACE}/configmaps/{name}"
    connection = http.client.HTTPSConnection(server.hostname, server.port, timeout=10, context=tls)
    try:
        connection.request("GET", path, headers={"Authorization": f"Bearer {token}",
                                                "Accept": "application/json"})
        response = connection.getresponse()
        return response.status, json.loads(response.read(65536))
    except (OSError, http.client.HTTPException) as error:
        lab.block(f"Owned ServiceAccount API request failed: {type(error).__name__}")
    finally:
        connection.close()


def run(lab):
    fixtures = json.loads((HERE / "fixtures.json").read_text())
    chain = live_chain(lab)
    lab.check(
        "green",
        "The runner-owned Kubernetes v1.36.1 API server has the explicit approved Node,RBAC chain",
        chain == fixtures["approved_chain"], chain,
    )

    for item in fixtures["inert_disallowed_chains"]:
        lab.check(
            "positive",
            f"Static {item['source']} review identifies AlwaysAllow in the inert authorizer chain",
            "AlwaysAllow" in item["chain"], {"source": item["source"], "chain": item["chain"]},
        )

    # Red baseline: prove the harmless record itself reaches admission before policy.
    first_chain = ",".join(fixtures["inert_disallowed_chains"][0]["chain"])
    before = submit_record(lab, "saf-0101-019-inert-denied-0", first_chain)
    lab.check(
        "red", "The inert AlwaysAllow record is admitted before the case policy is installed",
        before.returncode == 0, {"returncode": before.returncode, "response": before.stderr.strip()},
    )

    lab.create(policy_object())
    lab.create(policy_binding())
    deadline = time.monotonic() + 20
    denial = submit_record(lab, "saf-0101-019-inert-denied-0", first_chain)
    while denial.returncode == 0 and time.monotonic() < deadline:
        time.sleep(0.5)
        denial = submit_record(lab, "saf-0101-019-inert-denied-0", first_chain)
    for index, item in enumerate(fixtures["inert_disallowed_chains"]):
        denied = submit_record(
            lab, f"saf-0101-019-inert-denied-{index}", ",".join(item["chain"]),
        )
        lab.check(
            "green",
            f"The live policy returns the exact Forbidden decision for the inert {item['source']} record",
            denied.returncode != 0 and "(Forbidden)" in denied.stderr
            and POLICY in denied.stderr and DENIAL in denied.stderr,
            {"returncode": denied.returncode,
             "reason": "Forbidden" if "(Forbidden)" in denied.stderr else None,
             "policy": POLICY if POLICY in denied.stderr else None,
             "message": DENIAL if DENIAL in denied.stderr else denied.stderr.strip()},
        )
    approved = submit_record(lab, "saf-0101-019-inert-approved", ",".join(fixtures["approved_chain"]))
    lab.check(
        "positive", "The live policy preserves admission for a valid inert Node,RBAC record",
        approved.returncode == 0,
        {"returncode": approved.returncode, "response": approved.stderr.strip()},
    )

    # Use a real short-lived ServiceAccount token; no --as impersonation.
    lab.kubectl("create", "serviceaccount", ACCOUNT)
    for name in (ALLOWED, NEIGHBOR):
        lab.kubectl("create", "configmap", name, "--from-literal=fixture=synthetic")
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": ACCOUNT, "namespace": NAMESPACE},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                   "resourceNames": [ALLOWED], "verbs": ["get"]}],
    }
    binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": ACCOUNT, "namespace": NAMESPACE},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ACCOUNT},
        "subjects": [{"kind": "ServiceAccount", "name": ACCOUNT, "namespace": NAMESPACE}],
    }
    lab.create(role)
    lab.create(binding)
    token = create_sa_token(lab)
    server, tls = api_client_config(lab)

    allowed_status, allowed_body = service_account_get(lab, token, server, tls, ALLOWED)
    lab.check(
        "positive", "The genuine fixture ServiceAccount can read its one RBAC-authorized synthetic ConfigMap",
        allowed_status == 200 and allowed_body.get("metadata", {}).get("name") == ALLOWED,
        {"http_status": allowed_status, "resource": allowed_body.get("metadata", {}).get("name")},
    )
    denied_status, denied_body = service_account_get(lab, token, server, tls, NEIGHBOR)
    lab.check(
        "green", "The same ServiceAccount receives Kubernetes Forbidden for the neighboring synthetic ConfigMap",
        denied_status == 403 and denied_body.get("reason") == "Forbidden",
        {"http_status": denied_status, "reason": denied_body.get("reason"),
         "resource": NEIGHBOR},
    )
