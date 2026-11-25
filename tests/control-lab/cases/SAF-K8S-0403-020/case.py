"""Exercise actual kube-apiserver KMS v2 through a least-privilege Vault policy."""

import base64
import hashlib
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
OBSERVATIONS = DIRECTORY + "/key-operations"
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
MARKERS = {
    "fixture-policy-encrypted": "public-api-storage-marker",
    "fixture-kms-pre-rotation": "public-before-transit-rotation",
    "fixture-kms-rewrite-rotation": "public-record-for-transit-rewrite",
    "fixture-kms-post-rotation": "public-after-transit-rotation",
}
VALUE = base64.b64encode(b"public authorization fixture").decode()
SCOPE = (
    "Exercise the actual Kubernetes KMS v2 plugin at the API storage boundary and separate "
    "Vault policies for the authorized API integration and a distinct fixture workload; verify "
    "remote operation attribution and deny unrelated keys and administration. Rotate the local Transit key, "
    "read the native encrypted-record key IDs, migrate one record and compare cold recovery. Cloud provider "
    "key policy, service grants, managed identity and HSM configuration need separate evidence."
)


def secret(lab, name):
    lab.create({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name},
                "stringData": {"marker": MARKERS[name]}})


def envelope_key_version(lab, value):
    """Read field two of the pinned v1.36.1 EncryptedObject schema."""
    if not value.startswith(PREFIX):
        lab.block("Expected the case-owned KMS v2 envelope")
    envelope = value[len(PREFIX):]
    offset = 0
    version = None

    def varint():
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            if offset >= len(envelope):
                lab.block("Truncated fixture envelope field")
            byte = envelope[offset]
            offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
        lab.block("Invalid fixture envelope field")

    while offset < len(envelope):
        field, wire = divmod(varint(), 8)
        if wire == 0:
            varint()
            continue
        if wire != 2:
            lab.block("Unexpected pinned fixture envelope wire type")
        length = varint()
        end = offset + length
        if end > len(envelope):
            lab.block("Invalid pinned fixture envelope field size")
        if field == 2:
            key_id = envelope[offset:end]
            known = {f"{KEY}-v{candidate}".encode(): candidate for candidate in (1, 2)}
            if version is not None or key_id not in known:
                lab.block("Expected exactly one recognized fixture storage key ID")
            version = known[key_id]
        offset = end
    if version is None:
        lab.block("The fixture KMS envelope did not contain its key ID")
    return version


def stored(lab, name, *, digest=False):
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
    result = {"kms_envelope": value.startswith(PREFIX), "marker_visible": MARKERS[name].encode() in value}
    if digest:
        result["record_digest"] = hashlib.sha256(value).hexdigest()
        result["transit_version"] = envelope_key_version(lab, value)
    return result


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
    lab.command("docker", "exec", node, "sh", "-ceu", 'umask 077; : >"$1"',
                "fixture-key-observations", OBSERVATIONS)
    lab.command("docker", "exec", "-d", node, DIRECTORY + "/bridge", SOCKET,
                f"https://{ip}:8200", vault.HOST, DIRECTORY + "/ca.pem", DIRECTORY + "/token", KEY,
                OBSERVATIONS)
    deadline = time.monotonic() + 18
    while time.monotonic() < deadline:
        if lab.command("docker", "exec", node, "test", "-S", SOCKET, allow_failure=True).returncode == 0:
            return
        time.sleep(.5)
    lab.block("The KMS v2 bridge did not expose its Unix socket")


def key_operations(lab, node):
    result = lab.command("docker", "exec", node, "cat", OBSERVATIONS)
    rows = result.stdout.splitlines()
    if any(not row.startswith(("status-v", "encrypt-v", "decrypt-v")) for row in rows):
        lab.block("The case-owned KMS bridge returned an unexpected observation")
    return rows


def wait_key_operation(lab, node, operation, start, timeout=85):
    expected = operation
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = key_operations(lab, node)
        if expected in rows[start:]:
            return rows
        time.sleep(1)
    lab.block(f"The case-owned KMS bridge did not observe {operation}")


def restart_api(lab, node):
    previous, = api_id(lab, node)
    lab.command("docker", "exec", node, "crictl", "stop", "--timeout", "1", previous)
    new_api(lab, node, previous)


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
    name = "fixture-policy-encrypted"
    secret(lab, name)
    observed = stored(lab, name)
    lab.check("green", "The actual API writes an encrypted envelope while Vault denies unwanted keys and administration",
              observed == {"kms_envelope": True, "marker_visible": False} and set(denied.values()) == {403} and app_ok,
              {"authority_http_denials": denied, "approved_workload_other_key": app_ok, "actual_secret_envelope": observed})

    restart_api(lab, node)
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

    # Exercise Vault Transit KEK rotation using only this case's root token.
    # Keep old Transit versions enabled; retirement is intentionally out of scope.
    secret(lab, "fixture-kms-pre-rotation")
    secret(lab, "fixture-kms-rewrite-rotation")
    old_records = {
        name: stored(lab, name, digest=True)
        for name in ("fixture-kms-pre-rotation", "fixture-kms-rewrite-rotation")
    }
    old_reads = all(api_readable(lab, name) for name in old_records)
    events = key_operations(lab, node)
    old_writes_v1 = ("encrypt-v1" in events and "status-v1" in events
                     and all(row["transit_version"] == 1 for row in old_records.values()))
    lab.check("positive", "Two named API records use Transit v1 before rotation",
              old_reads and old_writes_v1 and all(
                  row["kms_envelope"] and not row["marker_visible"] for row in old_records.values()),
              {"exact_owned_records_encrypted": all(row["kms_envelope"] and not row["marker_visible"]
                                                     for row in old_records.values()),
               "exact_authorized_reads": old_reads, "provider_v1_observed": old_writes_v1})

    before_rotation_events = len(events)
    vault.required(lab, "transit/keys/" + KEY + "/rotate", token=root, body={}, method="POST")
    key_state = vault.required(lab, "transit/keys/" + KEY, token=root)
    latest_version = (key_state.get("data") or {}).get("latest_version")
    status_v2 = wait_key_operation(lab, node, "status-v2", before_rotation_events)
    # The API may wrap its new seed during Status processing and reuse it for
    # later writes. Observe that provider event since rotation, then prove the
    # new write's key ID in the exact native stored envelope independently.
    writes_v2 = wait_key_operation(lab, node, "encrypt-v2", before_rotation_events, timeout=25)
    secret(lab, "fixture-kms-post-rotation")
    post_record = stored(lab, "fixture-kms-post-rotation", digest=True)
    old_unchanged = all(stored(lab, name, digest=True)["record_digest"] == row["record_digest"]
                        for name, row in old_records.items())
    old_reads_after_rotation = all(api_readable(lab, name) for name in old_records)
    lab.check("green", "Transit rotation is observed by KMS v2 before new API writes while old records still read",
              latest_version == 2 and "encrypt-v2" in writes_v2[before_rotation_events:]
              and post_record["transit_version"] == 2 and post_record["kms_envelope"] and not post_record["marker_visible"]
              and old_unchanged and old_reads_after_rotation,
              {"latest_transit_version": latest_version,
               "api_observed_status_v2": "status-v2" in status_v2[before_rotation_events:],
               "api_seed_wrap_observed_v2": "encrypt-v2" in writes_v2[before_rotation_events:],
               "post_rotation_record_key_version": post_record["transit_version"],
               "post_rotation_record_encrypted": post_record["kms_envelope"] and not post_record["marker_visible"],
               "pre_rotation_records_unchanged": old_unchanged,
               "pre_rotation_records_readable": old_reads_after_rotation})

    # Rewrite exactly one named pre-rotation record after v2 is observed.
    rewrite_name = "fixture-kms-rewrite-rotation"
    lab.kubectl("annotate", "secret/" + rewrite_name, "saf.example.org/transit-rotation=rewritten")
    rewritten = stored(lab, rewrite_name, digest=True)
    rewritten_read = api_readable(lab, rewrite_name)
    new_read = api_readable(lab, "fixture-kms-post-rotation")
    lab.check("positive", "A scoped API rewrite migrates the selected v1 record and preserves exact reads",
              rewritten["record_digest"] != old_records[rewrite_name]["record_digest"]
              and rewritten["transit_version"] == 2 and rewritten["kms_envelope"] and not rewritten["marker_visible"]
              and rewritten_read and new_read,
              {"selected_record_changed": rewritten["record_digest"] != old_records[rewrite_name]["record_digest"],
               "selected_record_still_encrypted": rewritten["kms_envelope"] and not rewritten["marker_visible"],
               "rewritten_record_key_version": rewritten["transit_version"],
               "selected_and_new_records_read_exactly": rewritten_read and new_read})

    before_cold = len(key_operations(lab, node))
    restart_api(lab, node)
    cold_reads = all(api_readable(lab, name) for name in MARKERS)
    cold_events = key_operations(lab, node)[before_cold:]
    saw_v1_decrypt = "decrypt-v1" in cold_events
    saw_v2_decrypt = "decrypt-v2" in cold_events
    lab.check("positive", "A cold API reads all four exact Secrets using retained Transit key versions",
              cold_reads and saw_v1_decrypt and saw_v2_decrypt,
              {"all_exact_fixture_reads": cold_reads,
               "cold_provider_decrypt_versions": {"v1": saw_v1_decrypt, "v2": saw_v2_decrypt}})

    (lab.evidence / "kms-transit-rotation-observations.json").write_text(json.dumps({
        "case_local_rotation": True,
        "latest_transit_version": latest_version,
        "provider_operations": {"v1_write_observed": old_writes_v1,
                                 "v2_status_observed": "status-v2" in status_v2[before_rotation_events:],
                                 "v2_write_observed": "encrypt-v2" in writes_v2[before_rotation_events:],
                                 "cold_v1_decrypt_observed": saw_v1_decrypt,
                                 "cold_v2_decrypt_observed": saw_v2_decrypt},
        "exact_fixture_reads": cold_reads,
        "pre_rotation_untouched_record_unchanged": stored(lab, "fixture-kms-pre-rotation", digest=True)["record_digest"]
        == old_records["fixture-kms-pre-rotation"]["record_digest"],
        "rewritten_record_encrypted": rewritten["kms_envelope"] and not rewritten["marker_visible"],
        "provider_versions_retired": False,
    }, indent=2) + "\n")
