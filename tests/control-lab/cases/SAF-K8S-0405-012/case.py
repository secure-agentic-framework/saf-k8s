"""Demonstrate an actual second factor at an isolated OIDC provider."""
import base64
from contextlib import contextmanager
from hashlib import sha1, sha256
import hmac
from html.parser import HTMLParser
from http.cookiejar import CookieJar
import importlib.util
import json
from pathlib import Path
import secrets
import selectors
import ssl
import subprocess
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, HTTPSHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
REALM = "fixture-mfa"
CLIENT = "fixture-mfa-relying-party"
SUBJECT = "fixture-privileged-reviewer"
SCOPE = (
    "A real owned Keycloak authentication flow observes password-only access before "
    "enrollment, requires a real time-based possession factor for a clean session after "
    "enrollment, and issues an OpenID Connect authorization code for the intended fixture "
    "subject only after the verifier accepts the new code. This covers a provider flow "
    "and does not establish production Kubernetes, cloud or recovery-path coverage."
)


def provider_module():
    path = ROOT / "SAF-K8S-0405-017" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_fixture_password_provider", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class LoginForms(HTMLParser):
    def __init__(self, body):
        super().__init__()
        self.forms = {}
        self.current = None
        self.feed(body)

    def handle_starttag(self, tag, fields):
        values = dict(fields)
        if tag == "form" and values.get("id") and values.get("action"):
            self.current = (values["action"], {})
            self.forms[values["id"]] = self.current
        elif tag == "input" and self.current and values.get("name"):
            self.current[1][values["name"]] = values.get("value") or ""

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None

    def select(self, field):
        return next((form for form in self.forms.values() if field in form[1]), None)


class Browser:
    def __init__(self, lab, issuer, trust):
        self.lab = lab
        self.issuer = issuer
        self.return_to = issuer + "/fixture-local-callback"
        self.state = secrets.token_urlsafe(20)
        self.verifier = secrets.token_urlsafe(36)
        self.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=trust),
                                   HTTPCookieProcessor(CookieJar()), NoRedirect())

    def visit(self, url, form=None):
        for _ in range(8):
            if (urlsplit(url).scheme, urlsplit(url).netloc) != ("https", urlsplit(self.issuer).netloc):
                self.lab.block("The provider response tried to leave the owned loopback origin")
            if urlsplit(url).path == "/fixture-local-callback":
                payload = parse_qs(urlsplit(url).query)
                if payload.get("state") != [self.state] or len(payload.get("code", [])) != 1:
                    self.lab.block("The local relying party did not receive the expected authorization code")
                return None, payload["code"][0]
            body = urlencode(form).encode() if form is not None else None
            headers = {"User-Agent": "SAF local exercise browser"}
            if body is not None:
                headers["Origin"] = self.issuer
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            try:
                response = self.opener.open(Request(url, data=body, headers=headers), timeout=10)
            except HTTPError as error:
                response = error
            with response:
                if response.status in {301, 302, 303, 307, 308} and response.headers.get("Location"):
                    url = urljoin(url, response.headers["Location"])
                    form = None
                    continue
                page = response.read().decode()
                if response.status != 200:
                    known = {
                        "invalid parameter: redirect_uri": "invalid redirect URI",
                        "invalid parameter: code_challenge": "invalid PKCE challenge",
                        "https required": "transport required by the fixture realm",
                        "cookie not found": "missing local browser session cookie",
                        "invalid username or password": "fixture credentials were rejected",
                        "session not active": "local session inactive",
                        "client not found": "fixture client unavailable",
                    }
                    reason = next((label for text, label in known.items() if text in page.casefold()),
                                  "unclassified fixture response")
                    endpoint = urlsplit(url).path.rsplit("/", 1)[-1]
                    self.lab.block(f"The owned browser flow returned HTTP {response.status} at {endpoint}: {reason}")
                return LoginForms(page), None
        self.lab.block("The owned browser flow did not reach a form or the local callback")

    def login(self, password):
        challenge = base64.urlsafe_b64encode(sha256(self.verifier.encode()).digest()).decode().rstrip("=")
        params = {"client_id": CLIENT, "redirect_uri": self.return_to, "state": self.state,
                  "response_type": "code", "scope": "openid profile", "prompt": "login",
                  "code_challenge_method": "S256", "code_challenge": challenge}
        forms, code = self.visit(self.issuer + f"/realms/{REALM}/protocol/openid-connect/auth?" +
                                 urlencode(params))
        form = forms.select("password") if forms else None
        if code or not form:
            self.lab.block("The owned provider did not present the password form")
        return self.submit(form, username=SUBJECT, password=password)

    def submit(self, form, **fields):
        action, existing = form
        return self.visit(urljoin(self.issuer + "/", action), dict(existing, **fields))

    def verified_subject(self, idp, code, subject_id):
        if not code:
            return False
        r = f"/realms/{REALM}/protocol/openid-connect"
        status, creds = idp.request(r + "/token", "POST", form={
            "grant_type": "authorization_code", "client_id": CLIENT, "code": code,
            "redirect_uri": self.return_to, "code_verifier": self.verifier,
        })
        if status != 200 or not creds.get("id_token") or not creds.get("access_token"):
            return False
        found, info = idp.request(r + "/userinfo", token=creds["access_token"])
        return found == 200 and info.get("sub") == subject_id and info.get("preferred_username") == SUBJECT


def setup(lab, idp, provider, admin, password):
    status, creds = idp.sign_in("master", "admin-cli", provider.ADMIN, admin)
    if status != 200 or not creds.get("access_token"):
        lab.block("The case-owned identity-provider administration session was unavailable")
    idp.admin = creds["access_token"]
    config = {"realm": REALM, "enabled": True, "otpPolicyType": "totp",
              "otpPolicyAlgorithm": "HmacSHA1", "otpPolicyDigits": 6, "otpPolicyPeriod": 30,
              "clients": [{"clientId": CLIENT, "enabled": True, "publicClient": True,
                           "directAccessGrantsEnabled": False, "standardFlowEnabled": True,
                           "redirectUris": [idp.base + "/fixture-local-callback"],
                           "attributes": {"pkce.code.challenge.method": "S256"}}]}
    realm_status, _ = idp.admin_request("", "POST", config)
    created, _ = idp.admin_request(f"/{REALM}/users", "POST", {
        "username": SUBJECT, "enabled": True, "emailVerified": True,
        "firstName": "Fixture", "lastName": "Reviewer", "email": SUBJECT + "@example.invalid",
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    })
    inspected, actors = idp.admin_request(f"/{REALM}/users?{urlencode({'username': SUBJECT, 'exact': 'true'})}")
    if (realm_status, created, inspected) != (201, 201, 200) or len(actors) != 1:
        lab.block(f"Could not provision the isolated relying party and subject (HTTP {realm_status}/{created}/{inspected})")
    return actors[0]["id"]


def passcode(secret, counter):
    digest = hmac.new(secret.encode(), counter.to_bytes(8, "big"), sha1).digest()
    offset = digest[-1] & 15
    projected = int.from_bytes(digest[offset:offset+4], "big") & 0x7fffffff
    return f"{projected % 1000000:06d}"


def audit(lab, idp, trust, subject_id, password):
    baseline = Browser(lab, idp.base, trust)
    before, code = baseline.login(password)
    red = {"password_only_issued_consumable_code": before is None
           and baseline.verified_subject(idp, code, subject_id)}
    lab.check("red", "The same provider previously authenticated the subject after one factor",
              all(red.values()), red)

    status, _ = idp.admin_request(f"/{REALM}/users/{subject_id}", "PUT",
                                  {"requiredActions": ["CONFIGURE_TOTP"]})
    if status != 204:
        lab.block(f"Could not require enrollment for the fixture subject (HTTP {status})")
    enrollment = Browser(lab, idp.base, trust)
    forms, code = enrollment.login(password)
    form = forms.select("totpSecret") if forms and code is None else None
    if not form or not form[1].get("totpSecret"):
        lab.block("The owned provider did not require possession-factor enrollment")
    secret = form[1]["totpSecret"]
    if time.time() % 30 > 23:
        time.sleep(31 - time.time() % 30)
    used_counter = int(time.time()) // 30
    enrolled_forms, enrolled_code = enrollment.submit(
        form, totp=passcode(secret, used_counter), userLabel="fixture-provider-factor")
    enrolled = enrolled_forms is None and enrollment.verified_subject(idp, enrolled_code, subject_id)

    secured = Browser(lab, idp.base, trust)
    challenge, unexpected_code = secured.login(password)
    factor = challenge.select("otp") if challenge else None
    green = {"real_enrollment_accepted": enrolled, "fresh_password_session_requires_otp": bool(factor),
             "no_code_before_second_factor": unexpected_code is None}
    lab.check("green", "The provider gates a fresh authenticated session on the real possession factor",
              all(green.values()), green)

    now = int(time.time()) // 30
    if now == used_counter or time.time() % 30 > 23:
        time.sleep(31 - time.time() % 30)
    step = int(time.time()) // 30
    completed, issued_code = secured.submit(factor, otp=passcode(secret, step))
    final = {"unused_time_step": step > used_counter,
             "new_otp_allows_intended_provider_session": completed is None
             and secured.verified_subject(idp, issued_code, subject_id)}
    lab.check("positive", "A fresh second-factor response completes the real relying-party flow",
              all(final.values()), final)
    (lab.evidence / "mfa-provider-observations.json").write_text(json.dumps({
        "identity_provider": "Keycloak 26.8.2", "before": red, "required": green, "verified": final,
    }, indent=2) + "\n")


def install_tls(lab, provider, admin):
    image = provider.load_provider(lab)
    directory = lab.kubeconfig.parent / "mfa-serving"
    directory.mkdir(mode=0o700)
    certificate, private = directory / "tls.crt", directory / "tls.key"
    lab.command("openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                "-subj", "/CN=fixture-idp-loopback", "-addext", "subjectAltName=IP:127.0.0.1",
                "-out", str(certificate), "-keyout", str(private), timeout=30)
    private.chmod(0o600)
    secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": provider.NAME},
              "stringData": {"admin-password": admin, "tls.key": private.read_text(),
                             "tls.crt": certificate.read_text()}}
    created = subprocess.run(provider.kubectl(lab, "create", "-f", "-"), input=json.dumps(secret),
                             capture_output=True, text=True, timeout=20, env=lab.env)
    if created.returncode:
        lab.block("Could not create the private serving and bootstrap fixture inputs")
    labels = {"app": provider.NAME}
    container = {
        "name": "idp", "image": image, "imagePullPolicy": "Never",
        "args": ["start-dev", "--hostname-strict=false", "--http-enabled=false", "--https-port=8443",
                 "--https-certificate-file=/fixture-serving/tls.crt",
                 "--https-certificate-key-file=/fixture-serving/tls.key"],
        "env": [
            {"name": "KC_BOOTSTRAP_ADMIN_USERNAME", "value": provider.ADMIN},
            {"name": "KC_BOOTSTRAP_ADMIN_PASSWORD",
             "valueFrom": {"secretKeyRef": {"name": provider.NAME, "key": "admin-password"}}},
        ],
        "ports": [{"containerPort": 8443}],
        "readinessProbe": {"httpGet": {"path": "/realms/master/.well-known/openid-configuration",
                                      "port": 8443, "scheme": "HTTPS"}, "periodSeconds": 2},
        "resources": {"requests": {"cpu": "250m", "memory": "384Mi"}, "limits": {"memory": "1Gi"}},
        "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                            "runAsNonRoot": True, "runAsUser": 1000,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "volumeMounts": [{"name": "serving", "mountPath": "/fixture-serving", "readOnly": True}],
    }
    provider.resource(lab, "Deployment", spec={
        "replicas": 1, "selector": {"matchLabels": labels},
        "template": {"metadata": {"labels": labels}, "spec": {
            "automountServiceAccountToken": False, "containers": [container],
            "volumes": [{"name": "serving", "secret": {"secretName": provider.NAME,
                         "items": [{"key": name, "path": name} for name in ("tls.crt", "tls.key")]}}],
        }},
    })
    lab.kubectl("rollout", "status", f"deployment/{provider.NAME}", "--timeout=110s", timeout=120)
    return ssl.create_default_context(cafile=str(certificate))


@contextmanager
def forward_tls(lab, provider):
    command = provider.kubectl(lab, "port-forward", "--address", "127.0.0.1",
                               f"deployment/{provider.NAME}", ":8443")
    with subprocess.Popen(command, env=lab.env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True) as process:
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                if not ready.select(12):
                    lab.block("The owned TLS port-forward did not start")
                line = process.stdout.readline().strip()
            prefix = "Forwarding from 127.0.0.1:"
            if not line.startswith(prefix):
                lab.block("The owned TLS port-forward did not bind to loopback")
            port = int(line.removeprefix(prefix).split(" ", 1)[0])
            yield f"https://127.0.0.1:{port}"
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def run(lab):
    provider = provider_module()
    admin = secrets.token_urlsafe(32)
    password = secrets.token_urlsafe(30)
    trust = install_tls(lab, provider, admin)
    with forward_tls(lab, provider) as endpoint:
        idp = provider.Idp(endpoint)
        idp.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=trust), NoRedirect())
        subject_id = setup(lab, idp, provider, admin, password)
        audit(lab, idp, trust, subject_id, password)
