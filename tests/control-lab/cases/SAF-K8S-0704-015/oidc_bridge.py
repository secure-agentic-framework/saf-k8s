"""Bounded native JWT-authentication to Kubernetes RBAC fixture for 0704-015."""

import base64
import json
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.error
from urllib.parse import urlsplit
import urllib.request
from pathlib import Path

import yaml

from fixtures import container

ISSUER = "https://127.0.0.1:17443"
AUDIENCE = "saf-0704-015-oidc-fixture"
API_CONFIG = "/etc/kubernetes/pki/saf-0704-015-authentication.json"
API_MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"
API_BACKUP = "/etc/kubernetes/saf-0704-015-apiserver.yaml"
ISSUER_STATIC = "/etc/kubernetes/manifests/saf-0704-015-issuer.json"
ISSUER_ASSETS = "/etc/kubernetes/saf-0704-015-issuer"
IMAGE = (
    "docker.io/library/python:3.13.2-alpine@sha256:"
    "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
)
GROUP = "fixture-group-entitlement-readers"
GROUP_PREFIX = "oidc-fixture:"
OIDC_BINDING = "fixture-oidc-entitlement-read"
APPROVED = "entitlement-approved"
COMPARISON = "entitlement-comparison"
ALLOWED_MARKER = "approved-public-marker"


def _block(lab, message):
    lab.block(message)


def _openssl(lab, *args, input_bytes=None):
    try:
        result = subprocess.run(["openssl", *args], input=input_bytes,
                                capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        _block(lab, "Synthetic OIDC key setup did not complete")
    if result.returncode:
        _block(lab, "Synthetic OIDC key setup failed")
    return result.stdout


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _mint(lab, key, *, group, audience=AUDIENCE):
    now = int(time.time())
    header = {"alg": "RS256", "kid": "saf-0704-015-fixture", "typ": "JWT"}
    claims = {"iss": ISSUER, "aud": audience, "exp": now + 300, "iat": now - 5,
              "sub": "external-entitlement-reviewer", "groups": [group],
              "fixture_class": "entitlement-map"}
    unsigned = ".".join(_b64url(json.dumps(item, separators=(",", ":")).encode())
                        for item in (header, claims))
    signature = _openssl(lab, "dgst", "-sha256", "-sign", str(key),
                         input_bytes=unsigned.encode())
    return unsigned + "." + _b64url(signature)


def _prepare_keys(lab, temp):
    _openssl(lab, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=saf-0704-015-loopback-oidc",
             "-addext", "subjectAltName=IP:127.0.0.1",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-keyout", str(temp / "tls.key"), "-out", str(temp / "tls.crt"))
    _openssl(lab, "genrsa", "-out", str(temp / "signing.key"), "2048")
    modulus = _openssl(lab, "rsa", "-in", str(temp / "signing.key"),
                       "-noout", "-modulus")
    n_hex = modulus.decode("ascii").strip().split("=", 1)[1]
    public_jwk = {"kty": "RSA", "kid": "saf-0704-015-fixture", "alg": "RS256",
                  "use": "sig", "n": _b64url(bytes.fromhex(n_hex)), "e": "AQAB"}
    (temp / "jwks.json").write_text(json.dumps({"keys": [public_jwk]}, sort_keys=True))


def _start_issuer(lab, node, temp, source):
    shutil.copyfile(source, temp / "issuer.py")
    lab.command("docker", "exec", node, "crictl", "pull", IMAGE, timeout=120)
    lab.command("docker", "exec", node, "mkdir", "-p", ISSUER_ASSETS)
    for filename in ("tls.crt", "tls.key", "jwks.json", "issuer.py"):
        lab.command("docker", "cp", str(temp / filename),
                    node + ":" + ISSUER_ASSETS + "/" + filename)
    lab.command("docker", "exec", node, "chown", "65534:65534", ISSUER_ASSETS + "/tls.key")
    static_pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "saf-0704-015-issuer", "namespace": "kube-system"},
        "spec": {"hostNetwork": True, "restartPolicy": "Always",
                 "automountServiceAccountToken": False,
                 "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                     "seccompProfile": {"type": "RuntimeDefault"}},
                 "containers": [container(
                     "issuer", image=IMAGE, imagePullPolicy="Never",
                     command=["python3", "/issuer/issuer.py"],
                     volumeMounts=[{"name": "fixture", "mountPath": "/issuer", "readOnly": True}],
                     resources={"requests": {"cpu": "10m", "memory": "16Mi"},
                                "limits": {"cpu": "100m", "memory": "64Mi"}},
                     securityContext={"allowPrivilegeEscalation": False,
                                      "readOnlyRootFilesystem": True,
                                      "capabilities": {"drop": ["ALL"]}})],
                 "volumes": [{"name": "fixture", "hostPath": {
                     "type": "Directory", "path": ISSUER_ASSETS}}]},
    }
    lab.command("docker", "exec", "-i", node, "sh", "-ceu",
                'cat >/etc/kubernetes/saf-0704-015-issuer.tmp; mv '
                ' /etc/kubernetes/saf-0704-015-issuer.tmp "$1"',
                "install-oidc-issuer", ISSUER_STATIC, payload=json.dumps(static_pod))
    ready = lab.command("docker", "exec", node, "curl", "--noproxy", "*", "--silent",
                        "--show-error", "--fail", "--retry", "20", "--retry-connrefused",
                        "--retry-delay", "1", "--max-time", "20", "--cacert",
                        ISSUER_ASSETS + "/tls.crt", ISSUER + "/.well-known/openid-configuration",
                        timeout=28, allow_failure=True)
    if ready.returncode or json.loads(ready.stdout).get("issuer") != ISSUER:
        _block(lab, "Owned loopback OIDC issuer did not become ready")


def _api_container(lab, node):
    result = lab.command("docker", "exec", node, "crictl", "ps", "--name", "^kube-apiserver$", "-q",
                         timeout=10, allow_failure=True)
    values = result.stdout.splitlines()
    return values[0] if result.returncode == 0 and len(values) == 1 else None


def _wait_api(lab, node, previous, timeout=100):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = _api_container(lab, node)
        if current and current != previous:
            health = lab.kubectl("get", "--raw=/readyz", allow_failure=True, timeout=10)
            if health.returncode == 0 and health.stdout.strip() == "ok":
                return
        time.sleep(1)
    _block(lab, "Disposable API did not become Ready after authentication configuration change")


def _wait_ready(lab, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        health = lab.kubectl("get", "--raw=/readyz", allow_failure=True, timeout=10)
        if health.returncode == 0 and health.stdout.strip() == "ok":
            return
        time.sleep(1)
    _block(lab, "Disposable API did not return to Ready during OIDC cleanup")


def _configure_api(lab, node, temp):
    config = {
        "apiVersion": "apiserver.config.k8s.io/v1", "kind": "AuthenticationConfiguration",
        "jwt": [{"issuer": {"url": ISSUER, "audiences": [AUDIENCE],
                             "certificateAuthority": (temp / "tls.crt").read_text()},
                 "claimValidationRules": [{"claim": "fixture_class", "requiredValue": "entitlement-map"}],
                 "claimMappings": {"username": {"claim": "sub", "prefix": "oidc-fixture:"},
                                   "groups": {"claim": "groups", "prefix": GROUP_PREFIX}}}],
    }
    lab.command("docker", "exec", "-i", node, "sh", "-ceu", 'cat >"$1"',
                "fixture-auth-config", API_CONFIG, payload=json.dumps(config))
    source = lab.command("docker", "exec", node, "cat", API_MANIFEST).stdout
    manifest = yaml.safe_load(source)
    for item in manifest["spec"]["containers"]:
        if item["name"] == "kube-apiserver":
            args = item.get("command", [])
            if any(value.startswith(("--oidc-", "--authentication-config")) for value in args):
                _block(lab, "Disposable API already has OIDC/authentication-config flags")
            item["command"].append("--authentication-config=" + API_CONFIG)
            break
    else:
        _block(lab, "Disposable API manifest has no kube-apiserver container")
    lab.command("docker", "exec", "-i", node, "sh", "-ceu",
                'cp "$1" "$2"; cat >/etc/kubernetes/saf-0704-015-apiserver.tmp; '
                'mv /etc/kubernetes/saf-0704-015-apiserver.tmp "$1"',
                "activate-authentication", API_MANIFEST, API_BACKUP,
                payload=yaml.safe_dump(manifest, sort_keys=False))


def _restore_api(lab, node):
    lab.command("docker", "exec", node, "sh", "-ceu",
                'if test -f "$1"; then mv "$1" "$2"; fi; rm -f "$3" "$4"; rm -rf "$5"',
                "restore-authentication", API_BACKUP, API_MANIFEST, ISSUER_STATIC,
                API_CONFIG, ISSUER_ASSETS)


def _api_client(lab):
    config = yaml.safe_load(Path(lab.kubeconfig).read_text())
    context_name = config.get("current-context") or "kind-" + lab.cluster
    context = next(item for item in config["contexts"] if item["name"] == context_name)
    cluster_name = context["context"]["cluster"]
    cluster = next(item for item in config["clusters"] if item["name"] == cluster_name)["cluster"]
    ca = base64.b64decode(cluster["certificate-authority-data"]).decode("ascii")
    tls_context = ssl.create_default_context(cadata=ca)
    server = cluster["server"]
    endpoint = urlsplit(server)
    if endpoint.scheme != "https" or endpoint.hostname not in {"127.0.0.1", "localhost", "::1"}:
        _block(lab, "Fixture JWT requests require the exact owned loopback Kubernetes API")
    return server, tls_context


def _get_marker(lab, server, tls_context, token, name):
    url = (server.rstrip("/") + "/api/v1/namespaces/saf-test/configmaps/" + name)
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls_context))
        with opener.open(request, timeout=5) as response:
            if response.status != 200:
                _block(lab, "Unexpected status from disposable API marker read")
            body = json.load(response)
            marker = body.get("data", {}).get("marker")
            return response.status, marker == ALLOWED_MARKER if name == APPROVED else marker == "comparison-public-marker"
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        if status not in (401, 403):
            _block(lab, "Unexpected HTTP status from disposable API marker read")
        return status, False
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        _block(lab, "Disposable API marker request failed")


def run_native_oidc_checks(lab, *, here):
    node = lab.cluster + "-control-plane"
    old_api = _api_container(lab, node)
    if not old_api:
        _block(lab, "Owned API container was unavailable before the OIDC fixture")
    with tempfile.TemporaryDirectory(prefix="saf-0704-015-oidc-") as dirname:
        temp = Path(dirname)
        _prepare_keys(lab, temp)
        try:
            _start_issuer(lab, node, temp, here / "issuer.py")
            server, tls_context = _api_client(lab)
            approved_token = _mint(lab, temp / "signing.key", group=GROUP)
            other_group_token = _mint(lab, temp / "signing.key", group="fixture-group-unrelated")
            wrong_audience_token = _mint(lab, temp / "signing.key", group=GROUP, audience="saf-other-audience")
            baseline_status, baseline_marker = _get_marker(lab, server, tls_context, approved_token, APPROVED)
            lab.check("red", "The signed fixture JWT is not authenticated before its issuer is configured",
                      baseline_status == 401 and not baseline_marker,
                      {"unconfigured_jwt_rejected": baseline_status == 401})
            group_api = "rbac.authorization.k8s.io"
            lab.create({"apiVersion": f"{group_api}/v1", "kind": "RoleBinding",
                        "metadata": {"name": OIDC_BINDING},
                        "roleRef": {"apiGroup": group_api, "kind": "Role",
                                    "name": "fixture-entitlement-read"},
                        "subjects": [{"kind": "Group", "apiGroup": group_api,
                                      "name": GROUP_PREFIX + GROUP}]})
            _configure_api(lab, node, temp)
            _wait_api(lab, node, old_api)

            allowed_status, allowed_marker = _get_marker(lab, server, tls_context, approved_token, APPROVED)
            wrong_group_status, _ = _get_marker(lab, server, tls_context, other_group_token, APPROVED)
            wrong_audience_status, _ = _get_marker(lab, server, tls_context, wrong_audience_token, APPROVED)
            extra_object_status, _ = _get_marker(lab, server, tls_context, approved_token, COMPARISON)
            scoped = (allowed_status == 200 and allowed_marker and wrong_group_status == 403
                      and wrong_audience_status == 401 and extra_object_status == 403)
            lab.check("positive", "The native JWT authenticator maps the approved group to only its named RBAC read",
                      scoped,
                      {"mapped_group_marker_allowed": allowed_status == 200 and allowed_marker,
                       "unrelated_group_denied": wrong_group_status == 403,
                       "wrong_audience_rejected": wrong_audience_status == 401,
                       "unlisted_object_denied": extra_object_status == 403})

            lab.kubectl("delete", "rolebinding/" + OIDC_BINDING)
            deadline = time.monotonic() + 20
            while True:
                revoked_status, _ = _get_marker(lab, server, tls_context, approved_token, APPROVED)
                if revoked_status == 403 or time.monotonic() >= deadline:
                    break
                time.sleep(.5)
            lab.check("green", "Removing the scoped RoleBinding revokes the authenticated OIDC read",
                      revoked_status == 403, {"authenticated_group_without_binding_denied": revoked_status == 403})
        finally:
            active_api = _api_container(lab, node)
            has_backup = lab.command("docker", "exec", node, "sh", "-ceu", 'test -f "$1"',
                                     "check-auth-backup", API_BACKUP, allow_failure=True).returncode == 0
            _restore_api(lab, node)
            if has_backup:
                _wait_api(lab, node, active_api or old_api)
            else:
                _wait_ready(lab)
        restored_status, _ = _get_marker(lab, server, tls_context, approved_token, APPROVED)
        lab.check("positive", "The restored API is Ready and no longer authenticates the fixture issuer",
                  restored_status == 401, {"restored_fixture_jwt_rejected": restored_status == 401})
