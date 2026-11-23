"""Test real JWT authentication and RBAC lifecycle on the disposable Kubernetes API."""

import base64
from copy import deepcopy
import json
import shutil
import ssl
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler

import yaml

HERE = Path(__file__).resolve().parent
ISSUER = "https://127.0.0.1:17443"
AUDIENCE = "saf-human-fixture"
NS = "saf-test"
MARKER = "oidc-protected-marker"
GROUP = "oidc-fixture:readers"
ROLE = "fixture-oidc-marker"
CONFIG = "/etc/kubernetes/pki/saf-fixture-authentication.json"
MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"
BACKUP = "/etc/kubernetes/saf-fixture-apiserver.yaml"
STATIC = "/etc/kubernetes/manifests/saf-fixture-issuer.json"
ASSETS = "/etc/kubernetes/saf-fixture-issuer"
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
RESOURCE = f"/api/v1/namespaces/{NS}/configmaps/{MARKER}"
SELF = "/apis/authentication.k8s.io/v1/selfsubjectreviews"
SCOPE = (
    "Exercise structured human JWT authentication and separate RBAC decisions on an owned Kind "
    "API with a loopback HTTPS issuer and ephemeral in-memory test credentials. Enterprise identity "
    "provider login, MFA, session and offboarding systems require distinct evidence."
)


def openssl(lab, *args, input_bytes=None):
    # Private key and synthetic JWT material never goes through commands.log.
    try:
        result = subprocess.run(["openssl", *args], input=input_bytes, capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("The ephemeral signing fixture could not run OpenSSL")
    if result.returncode:
        lab.block("The ephemeral signing fixture could not prepare its keys")
    return result.stdout


def b64(blob):
    return base64.urlsafe_b64encode(blob).rstrip(b"=").decode("ascii")


def jwt(lab, private, payload):
    header = {"alg": "RS256", "kid": "fixture-rsa", "typ": "JWT"}
    fields = [b64(json.dumps(item, separators=(",", ":")).encode()) for item in (header, payload)]
    unsigned = ".".join(fields)
    signed = openssl(lab, "dgst", "-sha256", "-sign", str(private), input_bytes=unsigned.encode())
    return unsigned + "." + b64(signed)


def start_issuer(lab, node, temp):
    openssl(lab, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=synthetic-saf-oidc", "-addext", "subjectAltName=IP:127.0.0.1",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-keyout", str(temp / "tls.key"), "-out", str(temp / "tls.crt"))
    for key in ("approved.key", "untrusted.key"):
        openssl(lab, "genrsa", "-out", str(temp / key), "2048")
    modulus = openssl(lab, "rsa", "-in", str(temp / "approved.key"), "-noout", "-modulus")
    public = {"kty": "RSA", "kid": "fixture-rsa", "alg": "RS256", "use": "sig",
              "n": b64(bytes.fromhex(modulus.decode().strip().split("=", 1)[1])), "e": "AQAB"}
    (temp / "jwks.json").write_text(json.dumps({"keys": [public]}))
    shutil.copyfile(HERE / "issuer.py", temp / "issuer.py")
    # Pull through the fixture node's runtime to select its platform from the pinned index.
    lab.command("docker", "exec", node, "crictl", "pull", PYTHON, timeout=120)
    lab.command("docker", "exec", node, "mkdir", "-p", ASSETS)
    for filename in ("tls.crt", "tls.key", "jwks.json", "issuer.py"):
        lab.command("docker", "cp", str(temp / filename), node + ":" + ASSETS + "/" + filename)
    lab.command("docker", "exec", node, "chown", "65534:65534", ASSETS + "/tls.key")
    pod = {
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": "saf-fixture-issuer", "namespace": "kube-system"},
        "spec": {"hostNetwork": True, "automountServiceAccountToken": False,
                 "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                     "seccompProfile": {"type": "RuntimeDefault"}},
                 "containers": [{"name": "issuer", "image": PYTHON, "imagePullPolicy": "Never",
                                 "command": ["python3", "/issuer/issuer.py"],
                                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                     "capabilities": {"drop": ["ALL"]}},
                                 "volumeMounts": [{"name": "fixture", "mountPath": "/issuer", "readOnly": True}]}],
                 "volumes": [{"name": "fixture", "hostPath": {"type": "Directory", "path": ASSETS}}]},
    }
    lab.command("docker", "exec", "-i", node, "sh", "-ceu", 'cat >/etc/kubernetes/saf-issuer.tmp; mv /etc/kubernetes/saf-issuer.tmp "$1"',
                "install-issuer", STATIC, payload=json.dumps(pod))
    result = lab.command("docker", "exec", node, "curl", "--noproxy", "*", "--silent", "--show-error", "--fail",
                         "--retry", "16", "--retry-connrefused", "--retry-delay", "1", "--max-time", "20",
                         "--cacert", ASSETS + "/tls.crt", ISSUER + "/.well-known/openid-configuration",
                         timeout=28, allow_failure=True)
    if result.returncode or json.loads(result.stdout).get("issuer") != ISSUER:
        mirror = lab.kubectl("-n", "kube-system", "get", "pods", "-o", "wide", allow_failure=True)
        lab.block("The owned HTTPS issuer was unavailable: " + str(mirror.returncode))


def configure(lab, node, temp):
    config = {"apiVersion": "apiserver.config.k8s.io/v1", "kind": "AuthenticationConfiguration",
              "jwt": [{"issuer": {"url": ISSUER, "audiences": [AUDIENCE],
                                   "certificateAuthority": (temp / "tls.crt").read_text()},
                       "claimValidationRules": [{"claim": "fixture_class", "requiredValue": "human"}],
                       "claimMappings": {"username": {"claim": "sub", "prefix": "oidc-fixture:"},
                                         "groups": {"claim": "groups", "prefix": "oidc-fixture:"}}}]}
    lab.command("docker", "exec", "-i", node, "sh", "-ceu", 'cat >"$1"', "fixture-auth-config", CONFIG,
                payload=json.dumps(config))
    source = lab.command("docker", "exec", node, "cat", MANIFEST).stdout
    manifest = yaml.safe_load(source)
    replacement = deepcopy(manifest)
    api = next(container for container in replacement["spec"]["containers"] if container["name"] == "kube-apiserver")
    if any(value.startswith(("--oidc-", "--authentication-config")) for value in api["command"]):
        lab.block("The disposable API already has unexpected authentication settings")
    api["command"].append("--authentication-config=" + CONFIG)
    lab.command("docker", "exec", "-i", node, "sh", "-ceu",
                'cp "$1" "$2"; cat >/etc/kubernetes/saf-apiserver.tmp; mv /etc/kubernetes/saf-apiserver.tmp "$1"',
                "activate-authentication", MANIFEST, BACKUP, payload=yaml.safe_dump(replacement, sort_keys=False))


def client(lab):
    doc = yaml.safe_load(Path(lab.kubeconfig).read_text())["clusters"][0]["cluster"]
    ca = base64.b64decode(doc["certificate-authority-data"]).decode("ascii")
    tls = ssl.create_default_context(cadata=ca)
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=tls))

    def request(token, target):
        data = None
        headers = {"Authorization": "Bearer " + token}
        if target == SELF:
            data = json.dumps({"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"}).encode()
            headers["Content-Type"] = "application/json"
        req = Request(doc["server"] + target, data=data, headers=headers)
        try:
            with opener.open(req, timeout=4) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, {}
        except (URLError, TimeoutError, ConnectionError, OSError):
            return 0, {}
    return request


def wait_status(lab, request, token, path, target, description):
    deadline = time.monotonic() + 65
    while time.monotonic() < deadline:
        status, body = request(token, path)
        if status == target:
            return body
        time.sleep(1)
    lab.block(f"{description}; expected fixture HTTP {target}, received {status}")


def run(lab):
    node = lab.cluster + "-control-plane"
    request = client(lab)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": MARKER},
                "data": {"marker": "owned-oidc-read"}})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": ROLE},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [MARKER], "verbs": ["get"]}]})
    binding = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": ROLE},
               "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ROLE},
               "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "Group", "name": GROUP}]}
    lab.create(binding)

    with TemporaryDirectory(prefix="saf-oidc-") as dirname:
        temp = Path(dirname)
        start_issuer(lab, node, temp)
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "human-probe", "iat": now - 10,
                  "exp": now + 300, "groups": ["readers"], "fixture_class": "human"}
        signing_key = temp / "approved.key"
        approved = jwt(lab, signing_key, claims)
        baseline, _ = request(approved, RESOURCE)
        lab.check("red", "A correctly signed fixture credential is unauthenticated before configuring the OIDC issuer",
                  baseline == 401, {"before_issuer_http": baseline})
        configure(lab, node, temp)
        try:
            info = wait_status(lab, request, approved, SELF, 201, "Structured issuer did not authenticate the fixture")
            user = info.get("status", {}).get("userInfo", {})
            mapped = user.get("username") == "oidc-fixture:human-probe" and GROUP in user.get("groups", [])
            statuses = {}
            for name, changed in {"audience": {"aud": "other-audience"},
                                  "issuer": {"iss": "https://unknown.fixture.invalid"},
                                  "expired": {"exp": now - 90, "iat": now - 150},
                                  "required_claim": {"fixture_class": "workload"}}.items():
                bad = jwt(lab, signing_key, {**claims, **changed})
                statuses[name] = request(bad, RESOURCE)[0]
            wrong_key = jwt(lab, temp / "untrusted.key", claims)
            statuses["signature"] = request(wrong_key, RESOURCE)[0]
            lab.check("green", "The API maps the approved human claims and rejects invalid issuer, audience, signature, expiry and class",
                      mapped and set(statuses.values()) == {401}, {"claim_mapping_matches": mapped, "negative_http": statuses})
            actual = wait_status(lab, request, approved, RESOURCE, 200, "Mapped group did not receive fixture grant")
            marker = actual.get("data", {}).get("marker") == "owned-oidc-read"
            unbound = jwt(lab, signing_key, {**claims, "groups": ["unbound"]})
            unbound_http = request(unbound, RESOURCE)[0]
            lab.kubectl("delete", "rolebinding/" + ROLE)
            wait_status(lab, request, approved, RESOURCE, 403, "RoleBinding removal did not withdraw resource authorization")
            post_auth, _ = request(approved, SELF)
            lab.create(binding)
            again = wait_status(lab, request, approved, RESOURCE, 200, "Authorized fixture access did not return")
            restored = again.get("data", {}).get("marker") == "owned-oidc-read"
            lab.check("positive", "The mapped grant only authorizes its group and RBAC removal leaves the unexpired JWT authenticated",
                      marker and unbound_http == 403 and post_auth == 201 and restored,
                      {"marker_read": marker, "unbound_group_http": unbound_http, "authorization_removed_http": 403,
                       "authentication_remained_http": post_auth, "grant_restored": restored})
        finally:
            lab.command("docker", "exec", node, "sh", "-ceu", 'mv "$1" "$2"; rm -f "$3"',
                        "restore-authentication", BACKUP, MANIFEST, STATIC)
        wait_status(lab, request, approved, RESOURCE, 401, "Restored API did not disable the fixture issuer")
        deadline = time.monotonic() + 45
        api_ready = False
        while time.monotonic() < deadline:
            health = lab.kubectl("get", "--raw=/readyz", allow_failure=True, timeout=10)
            api_ready = health.returncode == 0 and health.stdout.strip() == "ok"
            if api_ready:
                break
            time.sleep(1)
        lab.check("positive", "The restored API is ready and rejects the temporary issuer again",
                  api_ready, {"restored_api_ready": api_ready, "fixture_issuer_disabled_http": 401})
    (lab.evidence / "human-oidc-observations.json").write_text(json.dumps({
        "before_issuer_http": baseline, "claim_mapping_matches": mapped, "negative_http": statuses,
        "approved_read": marker, "unbound_group_http": unbound_http, "revoke_rolebinding_http": 403,
        "unexpired_authentication_after_removal_http": post_auth, "rolebinding_restored_read": restored,
        "restored_api_ready": api_ready, "fixture_issuer_disabled_http": 401,
    }, indent=2) + "\n")
