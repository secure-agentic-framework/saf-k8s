"""Observe Secrets envelopes with the actual Kubernetes KMS v2 storage transformer."""

import base64
import io
import json
from pathlib import Path
import secrets
import subprocess
from tempfile import TemporaryDirectory
import tarfile
import time

import yaml

HERE = Path(__file__).resolve().parent
BUSYBOX = ("docker.io/library/busybox:1.37.0@sha256:"
           "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec")
SERVER = "kms.fixture.invalid"
DIRECTORY = "/etc/kubernetes/pki/saf-kms-fixture"
SOCKET = DIRECTORY + "/kms.sock"
CONFIG = DIRECTORY + "/encryption.json"
MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"
NS = "saf-test"
OLD = "fixture-kms-original"
NEW = "fixture-kms-new"
MARKERS = {OLD: "public-before-provider", NEW: "public-after-provider"}
PREFIX = b"k8s:enc:kms:v2:fixture-kms:"
SCOPE = (
    "Use native Kubernetes KMS v2 with an authenticated Unix plugin and a distinct isolated "
    "TLS wrapping service. Inspect exact owned Secret records, rewrite a pre-existing record "
    "and restart the API to exercise remote decryption. Actual managed-cloud custody, HSMs, "
    "IAM and production lifecycle require distinct evidence."
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


def launch_provider(lab, node, net, provider, temp):
    assets = temp / "assets"
    assets.mkdir(mode=0o700)
    cpu = lab.command("docker", "exec", node, "uname", "-m").stdout.strip()
    machine = {"aarch64": "arm64", "x86_64": "amd64"}.get(cpu)
    if not machine:
        lab.block("The KMS fixture does not have a supported build architecture")
    lab.command("env", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=" + machine, "go", "-C", str(HERE), "build",
                "-trimpath", "-mod=readonly", "-o", str(assets / "bridge"), ".", timeout=150)
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=" + SERVER,
                "-addext", "subjectAltName=DNS:" + SERVER, "-addext", "basicConstraints=critical,CA:TRUE",
                "-keyout", str(assets / "tls.key"), "-out", str(assets / "ca.crt"))
    auth = assets / "auth"
    auth.write_text(secrets.token_urlsafe(32))
    auth.chmod(0o600)
    lab.command("docker", "network", "create", "--internal", net)
    lab.command("docker", "network", "connect", net, node)
    lab.command("docker", "create", "--cap-drop", "ALL", "--user", "0:0", "--network", net,
                "--network-alias", SERVER, "--name", provider, BUSYBOX, "/tmp/fixture/bridge", "authority",
                "/tmp/fixture/ca.crt", "/tmp/fixture/tls.key", "/tmp/fixture/auth", timeout=70)
    # Normalize ownership inside the fixture without granting Docker root the
    # ability to bypass permissions. The protected archive is never logged.
    def owned(entry):
        entry.uid = entry.gid = 0
        entry.uname = entry.gname = "root"
        return entry
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w") as archive:
        archive.add(assets, arcname="fixture", filter=owned)
    try:
        copied = subprocess.run(["docker", "cp", "-", provider + ":/tmp/"], env=lab.env,
                                input=content.getvalue(), capture_output=True, timeout=25)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("The protected fixture provider files could not be installed")
    if copied.returncode:
        lab.block("Docker could not install the protected provider files")
    lab.command("docker", "start", provider)
    lab.command("docker", "exec", node, "mkdir", "-p", DIRECTORY)
    for filename in ("bridge", "ca.crt", "auth"):
        lab.command("docker", "cp", str(assets / filename), node + ":" + DIRECTORY + "/" + filename)
    lab.command("docker", "exec", "-d", node, DIRECTORY + "/bridge", "plugin", SOCKET,
                f"https://{SERVER}:19443", DIRECTORY + "/ca.crt", DIRECTORY + "/auth")
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if lab.command("docker", "exec", node, "test", "-S", SOCKET, allow_failure=True).returncode == 0:
            return
        time.sleep(.5)
    lab.block("The owned KMS plugin did not create its Unix socket")


def enable_kms(lab, node):
    config = {"apiVersion": "apiserver.config.k8s.io/v1", "kind": "EncryptionConfiguration",
              "resources": [{"resources": ["secrets"], "providers": [{"kms": {"apiVersion": "v2",
                          "name": "fixture-kms", "endpoint": "unix://" + SOCKET, "timeout": "3s"}}, {"identity": {}}]}]}
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


def counts(lab, provider):
    lines = lab.command("docker", "logs", provider).stdout.splitlines()
    return {op: lines.count("fixture-kms-" + op) for op in ("wrap", "unwrap")}


def run(lab):
    node = lab.cluster + "-control-plane"
    net = lab.cluster + "-key-network"
    provider = lab.cluster + "-key-authority"
    secret(lab, OLD)
    baseline = stored(lab, OLD)
    lab.check("red", "The unconfigured API writes the exact original Secret without a KMS envelope",
              baseline == {"kms_envelope": False, "marker_visible": True}, baseline)
    try:
        with TemporaryDirectory(prefix="saf-kms-build-") as root:
            launch_provider(lab, node, net, provider, Path(root))
        enable_kms(lab, node)
        secret(lab, NEW)
        current = stored(lab, NEW)
        prior_unwritten = stored(lab, OLD) == baseline
        remote_wrap = counts(lab, provider)["wrap"] > 0
        lab.check("green", "Native new writes use the KMS v2 envelope and the distinct remote authority wraps a key",
                  current == {"kms_envelope": True, "marker_visible": False} and prior_unwritten and remote_wrap,
                  {"new_envelope": current, "existing_record_initially_unchanged": prior_unwritten, "remote_wrap_called": remote_wrap})
        lab.kubectl("annotate", "secret/" + OLD, "saf.example.org/kms-migration=rewritten")
        migrated = stored(lab, OLD) == current
        before = counts(lab, provider)["unwrap"]
        previous, = api_id(lab, node)
        lab.command("docker", "exec", node, "crictl", "stop", "--timeout", "1", previous)
        new_api(lab, node, previous)
        available = all(api_readable(lab, name) for name in MARKERS)
        remote_unwrap = counts(lab, provider)["unwrap"] > before
        lab.check("positive", "Rewriting the old Secret migrates its envelope, and a fresh API reads both with remote key operations",
                  migrated and available and remote_unwrap,
                  {"prior_record_migrated": migrated, "both_api_reads_valid": available, "new_remote_unwrap_after_restart": remote_unwrap})
        (lab.evidence / "kms-integration-observations.json").write_text(json.dumps({
            "original_record": baseline, "new_record": current, "original_record_migrated": migrated,
            "remote_wrap": remote_wrap, "remote_unwrap_after_restart": remote_unwrap, "both_api_reads_valid": available,
            "provider_mode": "separate authenticated disposable TLS authority",
        }, indent=2) + "\n")
    finally:
        lab.command("docker", "rm", "-f", provider, allow_failure=True)
        lab.command("docker", "network", "disconnect", net, node, allow_failure=True)
        lab.command("docker", "network", "rm", net, allow_failure=True)
