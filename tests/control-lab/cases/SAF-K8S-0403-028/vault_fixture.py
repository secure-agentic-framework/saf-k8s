"""Private TLS Vault requests for case-owned Kind fixtures."""

import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import time

from fixtures import container, pod, ready

NS = "saf-test"
VAULT = "fixture-vault"
PROBE = "fixture-vault-admin"
VAULT_SA = "fixture-vault-reviewer"
TLS_SECRET = "fixture-vault-tls"
CA = "fixture-vault-public-ca"
HOST = VAULT + "." + NS + ".svc"
ADDRESS = "https://" + HOST + ":8200"
AUDIENCE = "https://vault.fixture.invalid/login"
VAULT_IMAGE = ("docker.io/hashicorp/vault:1.21.4@sha256:"
               "4e33b126a59c0c333b76fb4e894722462659a6bec7c48c9ee8cea56fccfd2569")
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
CLIENT = r'''
import json, ssl, sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

r = json.load(sys.stdin)
context = ssl.create_default_context(cafile="/fixture-ca/ca.crt")
client = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
headers = {"Content-Type": "application/json"}
if r.get("token"):
    headers["X-Vault-Token"] = r["token"]
body = r.get("body")
if r.get("login"):
    body = {"role": r["login"], "jwt": Path("/fixture-identity/token").read_text().strip()}
request = Request(r["address"] + "/v1/" + r["path"], headers=headers,
                  data=json.dumps(body).encode() if body is not None else None,
                  method=r["method"])
try:
    with client.open(request, timeout=4) as result:
        response = result.read()
        print(json.dumps([result.status, json.loads(response) if response else {}]))
except HTTPError as error:
    # A failure response can omit useful detail but never reaches retained output.
    response = error.read()
    print(json.dumps([error.code, json.loads(response) if response else {}]))
'''


def private(lab, *args, payload=None):
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
               "--namespace", NS, "--request-timeout=12s", *args]
    try:
        result = subprocess.run(command, env=lab.env, input=payload, text=True, capture_output=True, timeout=16)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def request(lab, path, *, token=None, body=None, method=None, via=PROBE, login=None):
    envelope = {"address": ADDRESS, "path": path, "token": token, "body": body, "login": login,
                "method": method or ("POST" if body is not None or login else "GET")}
    response = private(lab, "exec", "-i", via, "--", "python3", "-c", CLIENT, payload=json.dumps(envelope))
    if response is None:
        return 0, {}
    try:
        status, result = json.loads(response)
    except (TypeError, ValueError):
        return 0, {}
    return status, result


def required(lab, path, *, token=None, body=None, method=None, via=PROBE, login=None):
    code, result = request(lab, path, token=token, body=body, method=method, via=via, login=login)
    if code not in (200, 204):
        lab.block(f"Owned Vault fixture {path} returned HTTP {code}")
    return result


def workload(lab, name, *, identity=False, audience=AUDIENCE):
    mounts = [{"name": "ca", "mountPath": "/fixture-ca", "readOnly": True}]
    volumes = [{"name": "ca", "configMap": {"name": CA}}]
    fields = {}
    if identity:
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name},
                    "automountServiceAccountToken": False})
        fields["serviceAccountName"] = name
        mounts.append({"name": "identity", "mountPath": "/fixture-identity", "readOnly": True})
        volumes.append({"name": "identity", "projected": {"sources": [{"serviceAccountToken": {
            "audience": audience, "expirationSeconds": 600, "path": "token"}}]}})
    unit = container("probe", image=PYTHON, command=["sh", "-c", "sleep 420"], volumeMounts=mounts)
    lab.create(pod(name, [unit], automountServiceAccountToken=False, volumes=volumes, **fields))


def start(lab, *, auth=False, audit=False):
    with TemporaryDirectory(prefix="saf-vault-fixture-") as dirname:
        directory = Path(dirname)
        key, cert = directory / "key.pem", directory / "ca.pem"
        lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=" + HOST, "-addext", "subjectAltName=DNS:" + HOST,
                    "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", str(key), "-out", str(cert))
        lab.kubectl("create", "secret", "tls", TLS_SECRET, "--cert=" + str(cert), "--key=" + str(key), "-o", "name")
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CA},
                    "data": {"ca.crt": cert.read_text()}})
    settings = """disable_mlock = true
storage "inmem" {}
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/fixture-tls/tls.crt"
  tls_key_file = "/fixture-tls/tls.key"
}
"""
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": VAULT},
                "data": {"fixture.hcl": settings}})
    if auth:
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": VAULT_SA}})
        api = "rbac.authorization.k8s.io/v1"
        lab.create({"apiVersion": api, "kind": "ClusterRole", "metadata": {"name": VAULT_SA},
                    "rules": [{"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"]}]})
        lab.create({"apiVersion": api, "kind": "ClusterRoleBinding", "metadata": {"name": VAULT_SA},
                    "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": VAULT_SA},
                    "subjects": [{"kind": "ServiceAccount", "name": VAULT_SA, "namespace": NS}]})
    unit = container("vault", image=VAULT_IMAGE, command=["vault", "server", "-config=/fixture/fixture.hcl"],
                     env=[{"name": "VAULT_API_ADDR", "value": ADDRESS}],
                     resources={"requests": {"cpu": "80m", "memory": "90Mi"}, "limits": {"memory": "384Mi"}},
                     volumeMounts=[{"name": "configuration", "mountPath": "/fixture", "readOnly": True},
                                   {"name": "tls", "mountPath": "/fixture-tls", "readOnly": True},
                                   {"name": "audit", "mountPath": "/fixture-audit"}])
    fields = {"serviceAccountName": VAULT_SA} if auth else {}
    server = pod(VAULT, [unit], automountServiceAccountToken=auth, securityContext={"fsGroup": 65534},
                 volumes=[{"name": "configuration", "configMap": {"name": VAULT}},
                          {"name": "tls", "secret": {"secretName": TLS_SECRET, "defaultMode": 0o440}},
                          {"name": "audit", "emptyDir": {}}], **fields)
    server["metadata"]["labels"] = {"app": VAULT}
    lab.create(server)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": VAULT},
                "spec": {"selector": {"app": VAULT}, "ports": [{"port": 8200, "targetPort": 8200}]}})
    workload(lab, PROBE)
    ready(lab, VAULT)
    ready(lab, PROBE)
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        code, _ = request(lab, "sys/health")
        if code == 501:
            break
        time.sleep(.5)
    else:
        lab.block("The isolated Vault authority did not become available for initialization")
    state = required(lab, "sys/init", body={"secret_shares": 1, "secret_threshold": 1}, method="PUT")
    root = state["root_token"]
    required(lab, "sys/unseal", body={"key": state["keys_base64"][0]}, method="PUT")
    required(lab, "sys/mounts/transit", token=root, body={"type": "transit"})
    if audit:
        required(lab, "sys/audit/case", token=root, body={"type": "file",
                 "options": {"file_path": "/fixture-audit/events.jsonl"}})
    if auth:
        required(lab, "sys/auth/kubernetes", token=root, body={"type": "kubernetes"})
        required(lab, "auth/kubernetes/config", token=root,
                 body={"kubernetes_host": "https://kubernetes.default.svc:443", "disable_local_ca_jwt": False})
    return root


def permissions(lab, root, name, rules):
    text = "\n".join(f'path "{path}" {{ capabilities = {json.dumps(capabilities)} }}'
                     for path, capabilities in rules.items())
    required(lab, "sys/policies/acl/" + name, token=root, body={"policy": text}, method="PUT")


def scoped_token(lab, root, name):
    info = required(lab, "auth/token/create", token=root, body={"policies": [name],
                    "no_default_policy": True, "ttl": "10m"})
    return info["auth"]["client_token"]


def role(lab, root, name, account=None, audience=AUDIENCE):
    required(lab, "auth/kubernetes/role/" + name, token=root, body={
        "bound_service_account_names": [account or name], "bound_service_account_namespaces": [NS],
        "audience": audience, "token_policies": [name], "token_no_default_policy": True, "token_ttl": "10m"})


def audit_entries(lab):
    line = private(lab, "exec", VAULT, "--", "cat", "/fixture-audit/events.jsonl")
    if line is None:
        lab.block("The case-owned Vault audit device did not supply its scoped evidence")
    return [json.loads(row) for row in line.splitlines() if row.strip()]
