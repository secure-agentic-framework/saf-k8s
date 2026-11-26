"""Exercise password selection on a real disposable identity provider."""
from contextlib import contextmanager
import json
import secrets
import selectors
import string
import subprocess
import time
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
WRONG_SAMPLE = "fixture-known-wrong-password"
BLOCKLIST = "fixture-password-denylist.txt"
FAILURE_THRESHOLD = 2
QUICK_LOGIN_CHECK_MS = 1000
LOCK_SECONDS = 10
SCOPE = (
    "A real Keycloak verifier in a fresh local Kind cluster enforces minimum password length "
    "and a fixture-specific blocklist during password changes, accepts a long lowercase "
    "password with no character-class composition rules and authenticates the intended subject. "
    "It also compares two fixed wrong-password submissions with Keycloak brute-force detection "
    "disabled and enabled for owned test identities, verifies the effective temporary lock, "
    "preserves a healthy comparator and performs an authorized reset. This bounded reference "
    "does not establish production federation, broader blocklist coverage, distributed/network "
    "rate limiting, production thresholds, or non-password authenticator policies."
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
    return approved


def auth_failure(result):
    # Keycloak's token endpoint returns OAuth invalid_grant for the fixed bad sample
    # and for a correct password rejected by lockout. Never retain the response text.
    status, document = result
    return status == 400 and document.get("error") == "invalid_grant"


def realm_settings(idp, values):
    updated, _ = idp.admin_request(f"/{REALM}", "PUT", values)
    read_status, current = idp.admin_request(f"/{REALM}")
    matches = all(current.get(name) == value for name, value in values.items())
    return updated == 204 and read_status == 200 and matches


def clear_failures(idp, user_id):
    status, _ = idp.admin_request(
        f"/{REALM}/attack-detection/brute-force/users/{user_id}", "DELETE")
    return status == 204


def failed_attempt_protection(lab, idp, users, approved):
    target = users[USER]
    healthy = users["fixture-blocklist-subject"]
    healthy_password = "".join(secrets.choice(string.ascii_lowercase) for _ in range(24))
    if reset_password(idp, target, approved) != 204 or reset_password(
            idp, healthy, healthy_password) != 204:
        lab.block("Could not set approved credentials for owned failed-attempt comparators")

    # Baseline: the identical bounded wrong sample must not cause account lock while
    # the native Keycloak brute-force control is disabled.
    baseline_settings = {"bruteForceProtected": False, "permanentLockout": False}
    baseline_live = realm_settings(idp, baseline_settings)
    baseline_failures = [idp.sign_in(REALM, CLIENT, USER, WRONG_SAMPLE) for _ in range(2)]
    baseline_target_ok = idp.sign_in(REALM, CLIENT, USER, approved)
    baseline_healthy_ok = idp.sign_in(REALM, CLIENT, "fixture-blocklist-subject",
                                      healthy_password)
    health_status, _ = idp.request("/realms/master/.well-known/openid-configuration")
    baseline = {
        "protection_disabled_setting_is_live": baseline_live,
        "two_fixed_wrong_samples_return_invalid_grant": all(auth_failure(x) for x in baseline_failures),
        "target_correct_credential_still_works": baseline_target_ok[0] == 200,
        "healthy_comparator_works": baseline_healthy_ok[0] == 200,
        "provider_health_remains_available": health_status == 200,
    }
    lab.check("red", "Two fixed wrong samples without brute-force protection do not lock the owned identity",
              all(baseline.values()), baseline)

    # Threshold-only temporary lockout profile. The two attempts are separated by
    # more than the configured quick-login interval, so the threshold (not velocity)
    # is the cause of the observed lock.
    settings = {
        "bruteForceProtected": True,
        "permanentLockout": False,
        "failureFactor": FAILURE_THRESHOLD,
        "maxDeltaTimeSeconds": 60,
        "waitIncrementSeconds": LOCK_SECONDS,
        "maxFailureWaitSeconds": LOCK_SECONDS,
        "quickLoginCheckMilliSeconds": QUICK_LOGIN_CHECK_MS,
        "minimumQuickLoginWaitSeconds": 1,
    }
    settings_live = realm_settings(idp, settings)
    cleared_before = clear_failures(idp, target)
    authorized_before = idp.sign_in(REALM, CLIENT, USER, approved)
    failures = []
    lock_observed = {"status_endpoint_succeeded": False,
                     "threshold_failures_observed": False,
                     "account_temporarily_disabled": False}
    locked_correct = (0, {})
    healthy_during_lock = (0, {})
    provider_health = 0
    owner_recovery = False
    recovered_login = (0, {})
    try:
        if settings_live and cleared_before and authorized_before[0] == 200:
            failures.append(idp.sign_in(REALM, CLIENT, USER, WRONG_SAMPLE))
            time.sleep(QUICK_LOGIN_CHECK_MS / 1000 + 0.2)
            failures.append(idp.sign_in(REALM, CLIENT, USER, WRONG_SAMPLE))
            status_status, lock_state = idp.admin_request(
                f"/{REALM}/attack-detection/brute-force/users/{target}")
            lock_observed = {
                "status_endpoint_succeeded": status_status == 200,
                "threshold_failures_observed": lock_state.get("numFailures") == FAILURE_THRESHOLD,
                "account_temporarily_disabled": lock_state.get("disabled") is True,
            }
            locked_correct = idp.sign_in(REALM, CLIENT, USER, approved)
            healthy_during_lock = idp.sign_in(
                REALM, CLIENT, "fixture-blocklist-subject", healthy_password)
            provider_health, _ = idp.request("/realms/master/.well-known/openid-configuration")
        # The Admin REST API's per-user clear operation releases a temporary lock.
        owner_recovery = clear_failures(idp, target)
        recovered_login = idp.sign_in(REALM, CLIENT, USER, approved)
    finally:
        # Also restore the disposable subject if any HTTP request above raises.
        if not owner_recovery:
            clear_failures(idp, target)
    enabled = {
        "enabled_threshold_profile_is_live": settings_live,
        "previous_failures_cleared_before_test": cleared_before,
        "target_credential_was_valid_before_samples": authorized_before[0] == 200,
        "exactly_threshold_fixed_wrong_samples_rejected": len(failures) == FAILURE_THRESHOLD
        and all(auth_failure(x) for x in failures),
        "effective_lock_is_independently_observed": all(lock_observed.values()),
        "correct_target_credential_is_blocked_during_lock": auth_failure(locked_correct),
        "healthy_comparator_remains_usable": healthy_during_lock[0] == 200,
        "provider_health_remains_available": provider_health == 200,
        "authorized_owner_clear_releases_temporary_lock": owner_recovery,
        "target_recovers_with_original_approved_credential": recovered_login[0] == 200,
    }
    lab.check("green", "Enabled Keycloak protection locks only the thresholded fixture identity and authorized reset recovers it",
              all(enabled.values()), {**enabled, **lock_observed})
    (lab.evidence / "failed-attempt-protection-observations.json").write_text(json.dumps({
        "identity_provider": "Keycloak 26.8.2",
        "sample_count_per_profile": FAILURE_THRESHOLD,
        "wrong_sample_values_retained": False,
        "credential_or_token_values_retained": False,
        "protection_disabled": baseline,
        "protection_enabled": {**enabled, **lock_observed},
    }, indent=2) + "\n")


def run(lab):
    admin_password = secrets.token_urlsafe(32)
    install(lab, admin_password)
    with forward(lab) as endpoint:
        idp = Idp(endpoint)
        users = setup(lab, idp, admin_password)
        approved = audit(lab, idp, users)
        failed_attempt_protection(lab, idp, users, approved)
