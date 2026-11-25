"""Owned loopback OIDC issuer helpers adapted from the SAF-K8S-0402-007 fixture."""

import base64
import json
import shutil
import subprocess
import time


ISSUER = "https://127.0.0.1:17443"
AUDIENCE = "https://promotion.saf.invalid"
CONFIG = "/etc/kubernetes/pki/saf-fixture-authentication.json"
MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"
BACKUP = "/etc/kubernetes/saf-fixture-apiserver.yaml"
STATIC = "/etc/kubernetes/manifests/saf-fixture-issuer.json"
ASSETS = "/etc/kubernetes/saf-fixture-issuer"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13.2-alpine@sha256:"
    "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
)


def _openssl(lab, *args, input_bytes=None):
    # Never send private key or token contents through the logged lab command wrapper.
    try:
        result = subprocess.run(["openssl", *args], input=input_bytes,
                                capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("The synthetic issuer key fixture could not run OpenSSL")
    if result.returncode:
        lab.block("The synthetic issuer key fixture could not prepare its keys")
    return result.stdout


def _b64(blob):
    return base64.urlsafe_b64encode(blob).rstrip(b"=").decode("ascii")


def mint_jwt(lab, signing_key, claims):
    header = {"alg": "RS256", "kid": "fixture-rsa", "typ": "JWT"}
    parts = [_b64(json.dumps(item, separators=(",", ":")).encode())
             for item in (header, claims)]
    unsigned = ".".join(parts)
    signature = _openssl(lab, "dgst", "-sha256", "-sign", str(signing_key),
                         input_bytes=unsigned.encode())
    return unsigned + "." + _b64(signature)


def start_issuer(lab, node, temp, issuer_source):
    _openssl(lab, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=synthetic-saf-oidc", "-addext", "subjectAltName=IP:127.0.0.1",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-keyout", str(temp / "tls.key"), "-out", str(temp / "tls.crt"))
    for key in ("approved.key", "untrusted.key"):
        _openssl(lab, "genrsa", "-out", str(temp / key), "2048")
    modulus = _openssl(lab, "rsa", "-in", str(temp / "approved.key"), "-noout", "-modulus")
    public = {"kty": "RSA", "kid": "fixture-rsa", "alg": "RS256", "use": "sig",
              "n": _b64(bytes.fromhex(modulus.decode().strip().split("=", 1)[1])),
              "e": "AQAB"}
    (temp / "jwks.json").write_text(json.dumps({"keys": [public]}))
    shutil.copyfile(issuer_source, temp / "issuer.py")
    lab.command("docker", "exec", node, "crictl", "pull", PYTHON_IMAGE, timeout=120)
    lab.command("docker", "exec", node, "mkdir", "-p", ASSETS)
    for filename in ("tls.crt", "tls.key", "jwks.json", "issuer.py"):
        lab.command("docker", "cp", str(temp / filename), node + ":" + ASSETS + "/" + filename)
    lab.command("docker", "exec", node, "chown", "65534:65534", ASSETS + "/tls.key")
    pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "saf-fixture-issuer", "namespace": "kube-system"},
        "spec": {"hostNetwork": True, "automountServiceAccountToken": False,
                 "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                     "seccompProfile": {"type": "RuntimeDefault"}},
                 "containers": [{"name": "issuer", "image": PYTHON_IMAGE,
                                 "imagePullPolicy": "Never",
                                 "command": ["python3", "/issuer/issuer.py"],
                                 "securityContext": {"allowPrivilegeEscalation": False,
                                                     "readOnlyRootFilesystem": True,
                                                     "capabilities": {"drop": ["ALL"]}},
                                 "volumeMounts": [{"name": "fixture", "mountPath": "/issuer",
                                                   "readOnly": True}]}],
                 "volumes": [{"name": "fixture", "hostPath": {"type": "Directory",
                                                                  "path": ASSETS}}]},
    }
    lab.command("docker", "exec", "-i", node, "sh", "-ceu",
                'cat >/etc/kubernetes/saf-issuer.tmp; mv /etc/kubernetes/saf-issuer.tmp "$1"',
                "install-issuer", STATIC, payload=json.dumps(pod))
    check = lab.command("docker", "exec", node, "curl", "--noproxy", "*", "--silent",
                        "--show-error", "--fail", "--retry", "16", "--retry-connrefused",
                        "--retry-delay", "1", "--max-time", "20", "--cacert",
                        ASSETS + "/tls.crt", ISSUER + "/.well-known/openid-configuration",
                        timeout=28, allow_failure=True)
    if check.returncode or json.loads(check.stdout).get("issuer") != ISSUER:
        lab.block("The case-owned synthetic OIDC issuer did not become ready")


def api_container(lab, node):
    result = lab.command("docker", "exec", node, "crictl", "ps", "--name", "^kube-apiserver$", "-q",
                         timeout=10, allow_failure=True)
    running = result.stdout.splitlines()
    return running[0] if result.returncode == 0 and len(running) == 1 else None


def wait_api_replacement(lab, node, previous):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        current = api_container(lab, node)
        if current and current != previous:
            health = lab.kubectl("get", "--raw=/readyz", allow_failure=True, timeout=10)
            if health.returncode == 0 and health.stdout.strip() == "ok":
                return
        time.sleep(1)
    lab.block("The disposable API did not become ready in a replacement container")


def restore_api(lab, node):
    lab.command("docker", "exec", node, "sh", "-ceu",
                'if test -f "$1"; then mv "$1" "$2"; fi; rm -f "$3" "$4"; rm -rf "$5"',
                "restore-authentication", BACKUP, MANIFEST, STATIC, CONFIG, ASSETS)


def configure_api(lab, node, temp):
    config = {
        "apiVersion": "apiserver.config.k8s.io/v1", "kind": "AuthenticationConfiguration",
        "jwt": [{"issuer": {"url": ISSUER, "audiences": [AUDIENCE],
                             "certificateAuthority": (temp / "tls.crt").read_text()},
                 "claimValidationRules": [
                     {"claim": "fixture_class", "requiredValue": "human-review"}],
                 "claimMappings": {
                     "username": {"claim": "sub", "prefix": "oidc-fixture:"},
                     "groups": {"claim": "groups", "prefix": "oidc-fixture:"}}}],
    }
    lab.command("docker", "exec", "-i", node, "sh", "-ceu", 'cat >"$1"',
                "fixture-auth-config", CONFIG, payload=json.dumps(config))
    import yaml
    source = lab.command("docker", "exec", node, "cat", MANIFEST).stdout
    manifest = yaml.safe_load(source)
    for container in manifest["spec"]["containers"]:
        if container["name"] == "kube-apiserver":
            if any(value.startswith(("--oidc-", "--authentication-config"))
                   for value in container["command"]):
                lab.block("The disposable API already has unexpected authentication settings")
            container["command"].append("--authentication-config=" + CONFIG)
            break
    else:
        lab.block("The disposable API manifest has no kube-apiserver container")
    lab.command("docker", "exec", "-i", node, "sh", "-ceu",
                'cp "$1" "$2"; cat >/etc/kubernetes/saf-apiserver.tmp; '
                'mv /etc/kubernetes/saf-apiserver.tmp "$1"',
                "activate-authentication", MANIFEST, BACKUP,
                payload=yaml.safe_dump(manifest, sort_keys=False))
