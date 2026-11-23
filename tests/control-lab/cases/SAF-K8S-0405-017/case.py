"""Exercise password selection on a real disposable identity provider."""
from contextlib import contextmanager
import json
import secrets
import selectors
import string
import subprocess
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

NS = "saf-test"
NAME = "fixture-password-idp"
REALM = "fixture-verifier-policy"
CLIENT = "fixture-password-client"
USER = "fixture-password-subject"
ADMIN = "fixture-idp-owner"
IMAGE = "quay.io/keycloak/keycloak:26.8.2"
PLATFORMS = {
    "aarch64": "694f168ad7d7e4f6bfd95b228d14dcd5d0a8300b2aba8a6d95dcfc848c8aa92b",
    "arm64": "694f168ad7d7e4f6bfd95b228d14dcd5d0a8300b2aba8a6d95dcfc848c8aa92b",
    "x86_64": "75b5c435a83b530caba5923922f93d47b2e3f8b4ad9e79200581122996653e55",
    "amd64": "75b5c435a83b530caba5923922f93d47b2e3f8b4ad9e79200581122996653e55",
}
BLOCKED = "fixture-do-not-accept-this-candidate"
BLOCKLIST = "fixture-password-denylist.txt"
SCOPE = (
    "A real Keycloak verifier in a fresh local Kind cluster enforces minimum password length "
    "and a fixture-specific blocklist during password changes, accepts a long lowercase "
    "password with no character-class composition rules and authenticates the intended subject. "
    "This selected password-policy test does not exercise production federation, blocklist "
    "coverage, online attempt limits or non-password authenticators."
)


def kubectl(lab, *args):
    return ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "--namespace", NS, *args]


def resource(lab, kind, name=NAME, **fields):
    api = "apps/v1" if kind == "Deployment" else "v1"
    lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def load_provider(lab):
    def image_id(reference):
        response = lab.command("docker", "image", "inspect", "--format", "{{.Id}}",
                               reference, timeout=20, allow_failure=True)
        return response.stdout.strip() if response.returncode == 0 else None

    engine = lab.command("docker", "info", "--format", "{{.Architecture}}", timeout=20).stdout.strip()
    digest = PLATFORMS.get(engine)
    if digest is None:
        lab.block("No pinned provider manifest is configured for this Docker architecture")
    source = f"{IMAGE}@sha256:{digest}"
    cached = f"saf-k8s-fixture/keycloak:26.8.2-{digest[:12]}"
    expected = image_id(source)
    if expected is None:
        lab.command("docker", "pull", source, timeout=2400)
        expected = image_id(source)
    if not expected or not expected.startswith("sha256:"):
        lab.block("The pinned provider image is unavailable in the local Docker cache")
    existing = image_id(cached)
    if existing and existing != expected:
        lab.block("The local fixture tag already refers to a different image")
    if not existing:
        lab.command("docker", "image", "tag", source, cached, timeout=20)
    if image_id(cached) != expected:
        lab.block("Could not resolve the fixture tag to the pinned provider image")
    lab.command("kind", "load", "docker-image", cached, "--name", lab.cluster, timeout=240)
    return cached


def install(lab, admin_password):
    image = load_provider(lab)
    secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": NAME},
              "stringData": {"admin-password": admin_password}}
    created = subprocess.run(kubectl(lab, "create", "-f", "-"), input=json.dumps(secret),
                             capture_output=True, text=True, timeout=20, env=lab.env)
    if created.returncode:
        lab.block("Could not create the ephemeral identity-provider bootstrap input")
    resource(lab, "ConfigMap", data={BLOCKLIST: BLOCKED + "\n"})
    labels = {"app": NAME}
    container = {
        "name": "idp", "image": image, "imagePullPolicy": "Never",
        "args": ["start-dev", "--http-port=8080", "--hostname-strict=false"],
        "env": [
            {"name": "KC_BOOTSTRAP_ADMIN_USERNAME", "value": ADMIN},
            {"name": "KC_BOOTSTRAP_ADMIN_PASSWORD",
             "valueFrom": {"secretKeyRef": {"name": NAME, "key": "admin-password"}}},
        ],
        "ports": [{"containerPort": 8080}],
        "readinessProbe": {
            "httpGet": {"path": "/realms/master/.well-known/openid-configuration", "port": 8080},
            "periodSeconds": 2,
        },
        "resources": {"requests": {"cpu": "250m", "memory": "384Mi"},
                      "limits": {"memory": "1Gi"}},
        "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                            "runAsNonRoot": True, "runAsUser": 1000,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "volumeMounts": [{"name": "policy", "mountPath": "/opt/keycloak/data/password-blacklists",
                          "readOnly": True}],
    }
    resource(lab, "Deployment", spec={
        "replicas": 1, "selector": {"matchLabels": labels},
        "template": {"metadata": {"labels": labels}, "spec": {
            "automountServiceAccountToken": False, "containers": [container],
            "volumes": [{"name": "policy", "configMap": {"name": NAME}}],
        }},
    })
    lab.kubectl("rollout", "status", f"deployment/{NAME}", "--timeout=110s", timeout=120)


@contextmanager
def forward(lab):
    command = kubectl(lab, "port-forward", "--address", "127.0.0.1", f"deployment/{NAME}", ":8080")
    with subprocess.Popen(command, env=lab.env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True) as process:
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                if not ready.select(12):
                    lab.block("The owned identity-provider port-forward did not start")
                line = process.stdout.readline().strip()
            prefix = "Forwarding from 127.0.0.1:"
            if not line.startswith(prefix):
                lab.block("The owned identity-provider port-forward did not bind to loopback")
            port = int(line.removeprefix(prefix).split(" ", 1)[0])
            yield f"http://127.0.0.1:{port}"
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


class Idp:
    def __init__(self, base):
        self.base = base
        self.opener = build_opener(ProxyHandler({}))
        self.admin = None

    def request(self, path, method="GET", document=None, form=None, token=None):
        assert document is None or form is None
        headers = {}
        body = None
        if document is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(document).encode()
        if form is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = urlencode(form).encode()
        if token:
            headers["Authorization"] = "Bearer " + token
        request = Request(self.base + path, data=body, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=12)
        except HTTPError as error:
            response = error
        with response:
            data = response.read()
            return response.status, json.loads(data) if data else {}

    def sign_in(self, realm, client, user, password):
        return self.request(f"/realms/{realm}/protocol/openid-connect/token", "POST",
                            form={"client_id": client, "grant_type": "password",
                                  "username": user, "password": password,
                                  "scope": "openid profile"})

    def admin_request(self, path, method="GET", document=None):
        return self.request("/admin/realms" + path, method, document, token=self.admin)


def setup(lab, idp, password):
    code, response = idp.sign_in("master", "admin-cli", ADMIN, password)
    if code != 200 or not response.get("access_token"):
        lab.block("The case-owned identity-provider administration session was unavailable")
    idp.admin = response["access_token"]
    source = {"realm": REALM, "enabled": True,
              "clients": [{"clientId": CLIENT, "enabled": True, "publicClient": True,
                           "directAccessGrantsEnabled": True, "standardFlowEnabled": False}]}
    created, _ = idp.admin_request("", "POST", source)
    if created != 201:
        lab.block(f"Could not create the isolated realm (HTTP {created})")
    users = {}
    for name in (USER, "fixture-blocklist-subject"):
        created, _ = idp.admin_request(f"/{REALM}/users", "POST", {
            "username": name, "enabled": True, "emailVerified": True,
            "firstName": "Fixture", "lastName": "Reviewer", "email": name + "@example.invalid",
        })
        found, data = idp.admin_request(f"/{REALM}/users?{urlencode({'username': name, 'exact': 'true'})}")
        if created != 201 or found != 200 or len(data) != 1 or data[0]["username"] != name:
            lab.block(f"Could not provision one isolated fixture subject (HTTP {created}/{found})")
        users[name] = data[0]["id"]
    return users


def reset_password(idp, user, password):
    status, _ = idp.admin_request(f"/{REALM}/users/{user}/reset-password", "PUT",
                                  {"type": "password", "temporary": False, "value": password})
    return status


def audit(lab, idp, users):
    short = "fixture"
    main = users[USER]
    blocklist_user = users["fixture-blocklist-subject"]
    baseline = {
        "short_candidate_accepted_without_policy": reset_password(idp, main, short) == 204,
        "blocked_candidate_accepted_without_policy": reset_password(idp, blocklist_user, BLOCKED) == 204,
    }
    lab.check("red", "The same two candidate passwords are accepted before enforcement",
              all(baseline.values()), baseline)

    policy = f"length(15) and passwordBlacklist({BLOCKLIST})"
    updated, _ = idp.admin_request(f"/{REALM}", "PUT", {"passwordPolicy": policy})
    read_status, state = idp.admin_request(f"/{REALM}")
    if updated != 204 or read_status != 200:
        lab.block(f"Could not update and inspect the live password policy (HTTP {updated}/{read_status})")
    selection = {
        "expected_policy_is_live": state.get("passwordPolicy") == policy,
        "short_candidate_now_rejected": reset_password(idp, main, short) == 400,
        "long_blocklisted_candidate_now_rejected": reset_password(idp, blocklist_user, BLOCKED) == 400,
    }
    lab.check("green", "The verifier independently rejects the short and blocklisted changes",
              all(selection.values()), selection)

    approved = "".join(secrets.choice(string.ascii_lowercase) for _ in range(24))
    accepted = reset_password(idp, main, approved)
    login, credential = idp.sign_in(REALM, CLIENT, USER, approved)
    token = credential.get("access_token")
    user_status, user = (idp.request(f"/realms/{REALM}/protocol/openid-connect/userinfo", token=token)
                         if token else (0, {}))
    positive = {
        "valid_lowercase_only_change_accepted": accepted == 204,
        "provider_authenticates_selected_subject": login == 200 and user_status == 200
        and user.get("sub") == main and user.get("preferred_username") == USER,
        "blocked_change_does_not_relax_policy": reset_password(idp, main, BLOCKED) == 400,
    }
    lab.check("positive", "A long approved password without composition requirements works at the provider",
              all(positive.values()), positive)
    (lab.evidence / "password-policy-observations.json").write_text(json.dumps({
        "identity_provider": "Keycloak 26.8.2",
        "before": baseline, "enforced": selection, "approved": positive,
    }, indent=2) + "\n")


def run(lab):
    admin_password = secrets.token_urlsafe(32)
    install(lab, admin_password)
    with forward(lab) as endpoint:
        idp = Idp(endpoint)
        users = setup(lab, idp, admin_password)
        audit(lab, idp, users)
