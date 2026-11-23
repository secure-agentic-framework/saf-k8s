"""Exercise actual kube-apiserver KMS v2 through a least-privilege Vault policy."""

import base64
import json
from pathlib import Path
import runpy
import subprocess
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace

import yaml

HERE = Path(__file__).resolve().parent
vault = SimpleNamespace(**runpy.run_path(str(HERE / "vault_fixture.py")))
DIRECTORY = "/etc/kubernetes/pki/saf-vault-kms"
SOCKET = DIRECTORY + "/kms.sock"
CONFIG = DIRECTORY + "/encryption.json"
MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"
NS = "saf-test"
PREFIX = b"k8s:enc:kms:v2:vault-fixture:"
KEY = "fixture-api-storage"
OTHER = "fixture-application-key"
ENC = "transit/encrypt/"
DEC = "transit/decrypt/"
INTEGRATION = "fixture-control-plane-kms"
WORKLOAD = "fixture-application-actor"
MARKERS = {"fixture-policy-encrypted": "public-api-storage-marker"}
VALUE = base64.b64encode(b"public authorization fixture").decode()
SCOPE = (
    "Exercise the actual Kubernetes KMS v2 plugin at the API storage boundary and separate "
    "Vault policies for the authorized API integration and a distinct fixture workload; verify "
    "remote operation attribution and deny unrelated keys and administration. Cloud provider "
    "key policy, service grants, managed identity and HSM configuration need separate evidence."
)


def secret(lab, name):
    lab.create({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name},
                "stringData": {"marker": MARKERS[name]}})


def stored(lab, name):
    path = f"/registry/secrets/{NS}/{name}"
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "--request-timeout=10s", "-n", "kube-system", "exec", f"etcd-{lab.cluster}-control-plane",
            "-c", "etcd", "--", "etcdctl", "--endpoints=https://127.0.0.1:2379",
            "--cacert=/etc/kubernetes/pki/etcd/ca.crt", "--cert=/etc/kubernetes/pki/etcd/server.crt",
            "--key=/etc/kubernetes/pki/etcd/server.key", "get", path, "--write-out=json"]
    try:
        run = subprocess.run(args, env=lab.env, text=True, capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("The owned etcd fixture record could not be read")
    if run.returncode:
        lab.block("The owned etcd fixture did not return a record")
    matches = json.loads(run.stdout).get("kvs", [])
    if len(matches) != 1 or base64.b64decode(matches[0]["key"]).decode() != path:
        lab.block("The exact owned etcd fixture record was missing")
    value = base64.b64decode(matches[0]["value"])
    return {"kms_envelope": value.startswith(PREFIX), "marker_visible": MARKERS[name].encode() in value}


def wait_api(lab):
    deadline = time.monotonic() + 85
    while time.monotonic() < deadline:
        answer = lab.kubectl("get", "--raw=/readyz", timeout=10, allow_failure=True)
        if answer.returncode == 0 and answer.stdout.strip() == "ok":
            return
        time.sleep(1)
    lab.block("The disposable API with fixture KMS did not become ready")


def api_id(lab, node):
    result = lab.command("docker", "exec", node, "crictl", "ps", "--name", "kube-apiserver", "-q", allow_failure=True)
    return result.stdout.split() if result.returncode == 0 else []


def new_api(lab, node, previous):
    deadline = time.monotonic() + 70
    while time.monotonic() < deadline:
        ids = api_id(lab, node)
        if len(ids) == 1 and ids[0] != previous:
            wait_api(lab)
            return
        time.sleep(1)
    lab.block("The owned API server did not restart")


def enable_kms(lab, node):
    config = {"apiVersion": "apiserver.config.k8s.io/v1", "kind": "EncryptionConfiguration",
              "resources": [{"resources": ["secrets"], "providers": [{"kms": {"apiVersion": "v2",
                          "name": "vault-fixture", "endpoint": "unix://" + SOCKET, "timeout": "3s"}}, {"identity": {}}]}]}
    lab.command("docker", "exec", "-i", node, "sh", "-ceu", 'cat >"$1"', "fixture-kms-config", CONFIG,
                payload=json.dumps(config))
    previous, = api_id(lab, node)
    manifest = yaml.safe_load(lab.command("docker", "exec", node, "cat", MANIFEST).stdout)
    api = next(unit for unit in manifest["spec"]["containers"] if unit["name"] == "kube-apiserver")
    if any(arg.startswith("--encryption-provider-config") for arg in api["command"]):
        lab.block("Unexpected storage encryption fixture on the case-owned node")
    api["command"].append("--encryption-provider-config=" + CONFIG)
    lab.command("docker", "exec", "-i", node, "sh", "-ceu", 'cat > /etc/kubernetes/saf-kms-apiserver.tmp; mv /etc/kubernetes/saf-kms-apiserver.tmp "$1"',
                "fixture-kms-apiserver", MANIFEST, payload=yaml.safe_dump(manifest, sort_keys=False))
    new_api(lab, node, previous)


def api_readable(lab, name):
    data = lab.kubectl("get", "secret/" + name, "-o", "jsonpath={.data.marker}").stdout.strip()
    return base64.b64decode(data).decode() == MARKERS[name] if data else False


def plugin(lab, node, credential):
    ip = lab.kubectl("get", "service/" + vault.VAULT, "-o", "jsonpath={.spec.clusterIP}").stdout.strip()
    ca = lab.kubectl("get", "configmap/" + vault.CA, "-o", "jsonpath={.data.ca\\.crt}").stdout
    machine = lab.command("docker", "exec", node, "uname", "-m").stdout.strip()
    arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(machine)
    if not arch or not ip or not ca.startswith("-----BEGIN CERTIFICATE-----"):
        lab.block("The TLS Vault bridge prerequisites did not resolve")
    with TemporaryDirectory(prefix="saf-vault-kms-bridge-") as directory:
        binary = Path(directory) / "bridge"
        lab.command("env", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=" + arch, "go", "-C", str(HERE),
                    "build", "-trimpath", "-mod=readonly", "-o", str(binary), ".", timeout=150)
        lab.command("docker", "exec", node, "mkdir", "-p", DIRECTORY)
        lab.command("docker", "cp", str(binary), node + ":" + DIRECTORY + "/bridge")
    lab.command("docker", "exec", "-i", node, "sh", "-ceu", 'cat >"$1"', "fixture-vault-ca",
                DIRECTORY + "/ca.pem", payload=ca)
    command = ["docker", "exec", "-i", node, "sh", "-ceu", 'umask 077; cat >"$1"',
               "fixture-vault-token", DIRECTORY + "/token"]
    try:
        sent = subprocess.run(command, env=lab.env, text=True, input=credential, capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("The fixture Vault credential could not be installed")
    if sent.returncode:
        lab.block("The fixture Vault credential could not be installed")
    lab.command("docker", "exec", "-d", node, DIRECTORY + "/bridge", SOCKET,
                f"https://{ip}:8200", vault.HOST, DIRECTORY + "/ca.pem", DIRECTORY + "/token", KEY)
    deadline = time.monotonic() + 18
    while time.monotonic() < deadline:
        if lab.command("docker", "exec", node, "test", "-S", SOCKET, allow_failure=True).returncode == 0:
            return
        time.sleep(.5)
    lab.block("The KMS v2 bridge did not expose its Unix socket")


def record_has(entries, policy, path):
    matched = {}
    for entry in entries:
        request = entry.get("request") or {}
        policies = (entry.get("auth") or {}).get("policies") or []
        if request.get("path") == path and policy in policies:
            matched.setdefault(request.get("id"), set()).add(entry.get("type"))
    return any(types >= {"request", "response"} for types in matched.values())


def run(lab):
    root = vault.start(lab, audit=True)
    for key in (KEY, OTHER):
        vault.required(lab, "transit/keys/" + key, token=root, body={"type": "aes256-gcm96"})
    allowed_app = {ENC + OTHER: ["update"], DEC + OTHER: ["update"]}
    vault.permissions(lab, root, WORKLOAD, {**allowed_app, ENC + KEY: ["update"], DEC + KEY: ["update"]})
    app = vault.scoped_token(lab, root, WORKLOAD)
    old = vault.required(lab, ENC + KEY, token=app, body={"plaintext": VALUE})["data"]["ciphertext"]
    initial = vault.request(lab, DEC + KEY, token=app, body={"ciphertext": old})
    baseline = initial[0] == 200 and initial[1]["data"]["plaintext"] == VALUE
    lab.check("red", "A workload with an over-broad key grant can use the Secrets wrapping key",
              baseline, {"broad_workload_wrap_and_unwrap": baseline})

    vault.permissions(lab, root, WORKLOAD, allowed_app)
    vault.permissions(lab, root, INTEGRATION, {ENC + KEY: ["update"], DEC + KEY: ["update"],
                                                "transit/keys/" + KEY: ["read"]})
    integration = vault.scoped_token(lab, root, INTEGRATION)
    denied = {
        "workload_wrapping": vault.request(lab, ENC + KEY, token=app, body={"plaintext": VALUE})[0],
        "workload_unwrapping": vault.request(lab, DEC + KEY, token=app, body={"ciphertext": old})[0],
        "integration_unrelated_key": vault.request(lab, ENC + OTHER, token=integration, body={"plaintext": VALUE})[0],
        "integration_policy_admin": vault.request(lab, "sys/policies/acl/" + INTEGRATION,
                                                 token=integration, body={"policy": ""}, method="PUT")[0],
    }
    app_ciphertext = vault.required(lab, ENC + OTHER, token=app, body={"plaintext": VALUE})["data"]["ciphertext"]
    app_ok = vault.required(lab, DEC + OTHER, token=app,
                            body={"ciphertext": app_ciphertext})["data"]["plaintext"] == VALUE
    node = lab.cluster + "-control-plane"
    plugin(lab, node, integration)
    enable_kms(lab, node)
    name, = MARKERS
    secret(lab, name)
    observed = stored(lab, name)
    lab.check("green", "The actual API writes an encrypted envelope while Vault denies unwanted keys and administration",
              observed == {"kms_envelope": True, "marker_visible": False} and set(denied.values()) == {403} and app_ok,
              {"authority_http_denials": denied, "approved_workload_other_key": app_ok, "actual_secret_envelope": observed})

    previous, = api_id(lab, node)
    lab.command("docker", "exec", node, "crictl", "stop", "--timeout", "1", previous)
    new_api(lab, node, previous)
    readable = api_readable(lab, name)
    events = vault.audit_entries(lab)
    integration_seen = all(record_has(events, INTEGRATION, operation + KEY) for operation in (ENC, DEC))
    lab.check("positive", "A fresh API reads its Secret and provider audit attributes both key operations to the integration",
              readable and integration_seen,
              {"cold_api_read": readable, "authority_wrap_and_unwrap_attributed": integration_seen})
    (lab.evidence / "kms-key-privilege-observations.json").write_text(json.dumps({
        "broad_workload_initially_allowed": baseline, "authority_http_denials": denied, "other_workload_key_preserved": app_ok,
        "actual_secrets_envelope": observed, "cold_api_read": readable, "actual_operations_attributed": integration_seen,
        "cloud_key_policy_tested": False,
    }, indent=2) + "\n")
