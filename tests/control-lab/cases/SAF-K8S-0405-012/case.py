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
import socket
import ssl
import subprocess
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, HTTPSHandler, ProxyHandler, Request, build_opener

HERE = Path(__file__).resolve().parent
REALM = "fixture-mfa"
CLIENT = "fixture-mfa-relying-party"
SUBJECT = "fixture-privileged-reviewer"
ISSUER = "https://127.0.0.1:17443/realms/fixture-mfa"
LOCAL_PORT = 17443
API_AUDIENCE = "saf-k8s-mfa-api"
API_USERNAME_PREFIX = "keycloak-fixture:"
API_CONFIG = "/etc/kubernetes/pki/saf-0405-012-authentication.json"
API_MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"
API_BACKUP = "/etc/kubernetes/saf-0405-012-apiserver.yaml"
SCOPE = (
    "A real owned Keycloak authentication flow observes password-only access before "
    "enrollment, requires a real time-based possession factor for a clean session after "
    "enrollment, and requests an essential LoA 2 claim. Its audience-bound real access token "
    "is then evaluated by the run-owned Kubernetes API server: LoA 1 is refused, LoA 2 reads "
    "one inert ConfigMap and cannot read a second. This covers one pinned local provider/API/RBAC "
    "path and does not establish production assurance, other login paths, cloud or recovery coverage."
)


def provider_module():
    path = HERE.parent / "SAF-K8S-0405-017" / "case.py"
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

    def login(self, password, requested_acr=None):
        challenge = base64.urlsafe_b64encode(sha256(self.verifier.encode()).digest()).decode().rstrip("=")
        params = {"client_id": CLIENT, "redirect_uri": self.return_to, "state": self.state,
                  "response_type": "code", "scope": "openid profile", "prompt": "login",
                  "code_challenge_method": "S256", "code_challenge": challenge}
        if requested_acr is not None:
            params["claims"] = json.dumps({"id_token": {"acr": {
                "essential": True, "values": [str(requested_acr)]}}}, separators=(",", ":"))
        forms, code = self.visit(self.issuer + f"/realms/{REALM}/protocol/openid-connect/auth?" +
                                 urlencode(params))
        form = forms.select("password") if forms else None
        if code or not form:
            self.lab.block("The owned provider did not present the password form")
        forms, code = self.submit(form, username=SUBJECT, password=password)
        if requested_acr == 2 and forms is not None:
            # The documented step-up flow authenticates level 1 before it asks for OTP.
            return forms, code
        return forms, code

    def submit(self, form, **fields):
        action, existing = form
        return self.visit(urljoin(self.issuer + "/", action), dict(existing, **fields))

    def verified_credentials(self, idp, code, subject_id):
        if not code:
            return None
        r = f"/realms/{REALM}/protocol/openid-connect"
        status, creds = idp.request(r + "/token", "POST", form={
            "grant_type": "authorization_code", "client_id": CLIENT, "code": code,
            "redirect_uri": self.return_to, "code_verifier": self.verifier,
        })
        if status != 200 or not creds.get("id_token") or not creds.get("access_token"):
            return None
        found, info = idp.request(r + "/userinfo", token=creds["access_token"])
        return creds if found == 200 and info.get("sub") == subject_id and \
            info.get("preferred_username") == SUBJECT else None

    def verified_subject(self, idp, code, subject_id):
        return self.verified_credentials(idp, code, subject_id) is not None


def setup(lab, idp, provider, admin, password):
    status, creds = idp.sign_in("master", "admin-cli", provider.ADMIN, admin)
    if status != 200 or not creds.get("access_token"):
        lab.block("The case-owned identity-provider administration session was unavailable")
    idp.admin = creds["access_token"]
    realm_status, imported = idp.admin_request(f"/{REALM}")
    inspected, actors = idp.admin_request(f"/{REALM}/users?{urlencode({'username': SUBJECT, 'exact': 'true'})}")
    if (realm_status, inspected) != (200, 200) or len(actors) != 1 or \
            imported.get("browserFlow") != "browser" or \
            actors[0].get("username") != SUBJECT or \
            imported.get("attributes", {}).get("acr.loa.map") != '{"1":1,"2":2}':
        lab.block("The boot-imported realm baseline or synthetic subject is incomplete")
    client_status, clients = idp.admin_request(f"/{REALM}/clients?{urlencode({'clientId': CLIENT})}")
    mappers = {mapper.get("name"): mapper for mapper in clients[0].get("protocolMappers", [])} \
        if client_status == 200 and len(clients) == 1 else {}
    audience = mappers.get("fixture-api-audience", {})
    acr = mappers.get("acr loa level", {})
    if client_status != 200 or len(clients) != 1 or \
            audience.get("protocolMapper") != "oidc-audience-mapper" or \
            audience.get("config", {}).get("included.custom.audience") != API_AUDIENCE or \
            audience.get("config", {}).get("access.token.claim") != "true" or \
            acr.get("protocolMapper") != "oidc-acr-mapper" or \
            acr.get("config", {}).get("access.token.claim") != "true":
        lab.block("The imported OIDC client lacks the explicit audience or ACR mapper")
    client_uuid = clients[0]["id"]
    scope_status, scopes = idp.admin_request(f"/{REALM}/clients/{client_uuid}/default-client-scopes")
    if scope_status != 200 or not any(scope.get("name") == "basic" for scope in scopes):
        lab.block("Keycloak did not enroll the subject mapper's default basic scope")
    _configure_stepup_flow(lab, idp)
    return actors[0]["id"]


def _configure_stepup_flow(lab, idp):
    """Create the documented LoA 1 password / LoA 2 OTP flow through Keycloak 26.8 Admin API."""
    flows_status, flows = idp.admin_request(f"/{REALM}/authentication/flows")
    if flows_status != 200 or any(row.get("alias") == "fixture-browser-stepup" for row in flows):
        lab.block("The imported realm's flow baseline is absent or unexpectedly pre-mutated")
    created, _ = idp.admin_request(f"/{REALM}/authentication/flows", "POST", {
        "alias": "fixture-browser-stepup", "description": "Owned SAF LoA step-up flow",
        "providerId": "basic-flow", "topLevel": True, "builtIn": False,
    })
    if created != 201:
        lab.block("Could not create the fixture browser flow")

    def executions(flow):
        status, rows = idp.admin_request(f"/{REALM}/authentication/flows/{flow}/executions")
        if status != 200 or not isinstance(rows, list):
            lab.block("Could not inspect the fixture authentication flow")
        return rows

    def set_requirement(flow, row, requirement):
        changed = dict(row)
        changed["requirement"] = requirement
        status, _ = idp.admin_request(f"/{REALM}/authentication/flows/{flow}/executions",
                                     "PUT", changed)
        if status != 204:
            lab.block("Could not set an exact fixture authentication requirement")

    def add_execution(flow, provider_id, requirement):
        status, _ = idp.admin_request(
            f"/{REALM}/authentication/flows/{flow}/executions/execution", "POST",
            {"provider": provider_id})
        if status != 201:
            lab.block("Could not add a required fixture authenticator")
        rows = executions(flow)
        row = next((item for item in rows if item.get("providerId") == provider_id), None)
        if row is None:
            lab.block("The expected fixture authenticator was not returned by Keycloak")
        set_requirement(flow, row, requirement)
        return row

    def add_subflow(parent, alias, requirement):
        status, _ = idp.admin_request(
            f"/{REALM}/authentication/flows/{parent}/executions/flow", "POST",
            {"alias": alias, "type": "basic-flow", "provider": "basic-flow",
             "description": "Owned SAF fixture LoA condition"})
        if status != 201:
            lab.block("Could not add a fixture LoA subflow")
        row = next((item for item in executions(parent) if item.get("displayName") == alias), None)
        if row is None:
            lab.block("The fixture LoA subflow was not returned by Keycloak")
        set_requirement(parent, row, requirement)
        return alias

    add_execution("fixture-browser-stepup", "auth-cookie", "ALTERNATIVE")
    add_subflow("fixture-browser-stepup", "fixture-auth-flow", "ALTERNATIVE")
    for level, max_age, authenticator in ((1, 36000, "auth-username-password-form"),
                                          (2, 0, "auth-otp-form")):
        alias = f"fixture-loa-{level}"
        add_subflow("fixture-auth-flow", alias, "CONDITIONAL")
        condition = add_execution(alias, "conditional-level-of-authentication", "REQUIRED")
        configured, _ = idp.admin_request(
            f"/{REALM}/authentication/executions/{condition['id']}/config", "POST",
            {"alias": alias, "config": {"loa-condition-level": str(level),
                                         "loa-max-age": str(max_age)}})
        if configured != 201:
            lab.block("Could not configure the exact Keycloak LoA condition")
        add_execution(alias, authenticator, "REQUIRED")

    flows_status, flows = idp.admin_request(f"/{REALM}/authentication/flows")
    flow = next((row for row in flows if row.get("alias") == "fixture-browser-stepup"), None)
    realm_status, realm = idp.admin_request(f"/{REALM}")
    if flows_status != 200 or realm_status != 200 or flow is None:
        lab.block("Could not validate the completed fixture LoA flow")
    realm["browserFlow"] = flow["alias"]
    updated, _ = idp.admin_request(f"/{REALM}", "PUT", realm)
    if updated != 204:
        lab.block("Could not bind the fixture's documented step-up browser flow")
    verification, bound = idp.admin_request(f"/{REALM}")
    if verification != 200 or bound.get("browserFlow") != "fixture-browser-stepup":
        lab.block("The fixture LoA browser flow binding did not persist")


def passcode(secret, counter):
    digest = hmac.new(secret.encode(), counter.to_bytes(8, "big"), sha1).digest()
    offset = digest[-1] & 15
    projected = int.from_bytes(digest[offset:offset+4], "big") & 0x7fffffff
    return f"{projected % 1000000:06d}"


def audit(lab, idp, trust, subject_id, password):
    baseline = Browser(lab, idp.base, trust)
    before, code = baseline.login(password, requested_acr=1)
    baseline_credentials = baseline.verified_credentials(idp, code, subject_id)
    red = {"password_only_issued_consumable_code": before is None
           and baseline_credentials is not None}
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
    challenge, unexpected_code = secured.login(password, requested_acr=2)
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
    high_credentials = secured.verified_credentials(idp, issued_code, subject_id)
    final = {"unused_time_step": step > used_counter,
             "new_otp_allows_intended_provider_session": completed is None
             and high_credentials is not None}
    lab.check("positive", "A fresh second-factor response completes the real relying-party flow",
              all(final.values()), final)
    (lab.evidence / "mfa-provider-observations.json").write_text(json.dumps({
        "identity_provider": "Keycloak 26.8.2", "before": red, "required": green, "verified": final,
    }, indent=2) + "\n")
    if baseline_credentials is None or high_credentials is None:
        lab.block("The provider did not issue both expected in-memory OIDC sessions")
    return {"level1": baseline_credentials["access_token"],
            "level2": high_credentials["access_token"],
            "id_level1": baseline_credentials["id_token"],
            "id_level2": high_credentials["id_token"]}


def install_tls(lab, provider, admin, password):
    image = provider.load_provider(lab)
    directory = lab.kubeconfig.parent / "mfa-serving"
    directory.mkdir(mode=0o700)
    ca_key, ca_cert = directory / "fixture-ca.key", directory / "fixture-ca.crt"
    certificate, private = directory / "tls.crt", directory / "tls.key"
    request, ext = directory / "tls.csr", directory / "tls.ext"
    ext.write_text("subjectAltName=IP:127.0.0.1\n"
                   "basicConstraints=critical,CA:FALSE\n"
                   "keyUsage=critical,digitalSignature,keyEncipherment\n"
                   "extendedKeyUsage=serverAuth\n"
                   "subjectKeyIdentifier=hash\n"
                   "authorityKeyIdentifier=keyid,issuer\n")
    ext.chmod(0o600)
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "2", "-subj", "/CN=SAF fixture local CA",
                        "-addext", "basicConstraints=critical,CA:TRUE",
                        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                        "-addext", "subjectKeyIdentifier=hash", "-keyout", str(ca_key),
                        "-out", str(ca_cert)], capture_output=True, timeout=30, check=True)
        subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                        "-subj", "/CN=127.0.0.1", "-keyout", str(private),
                        "-out", str(request)], capture_output=True, timeout=30, check=True)
        subprocess.run(["openssl", "x509", "-req", "-in", str(request), "-CA", str(ca_cert),
                        "-CAkey", str(ca_key), "-CAcreateserial", "-days", "2", "-sha256",
                        "-extfile", str(ext), "-out", str(certificate)],
                       capture_output=True, timeout=30, check=True)
    except (OSError, subprocess.SubprocessError):
        lab.block("Could not create the short-lived local issuer certificate chain")
    for private_file in (ca_key, private):
        private_file.chmod(0o600)
    server_certificate = certificate.read_text() + ca_cert.read_text()
    realm = json.loads((HERE / "realm-fixture.json").read_text())
    if realm.get("realm") != REALM or realm.get("browserFlow") != "browser":
        lab.block("The static fixture realm import has unexpected identity or flow defaults")
    credentials = realm.get("users", [{}])[0].get("credentials", [])
    if len(credentials) != 1 or credentials[0].get("value") != "FIXTURE_PASSWORD_SENTINEL":
        lab.block("The fixture realm password placeholder is not exact")
    credentials[0]["value"] = password
    realm_payload = json.dumps(realm, separators=(",", ":"))
    secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": provider.NAME},
              "stringData": {"admin-password": admin, "tls.key": private.read_text(),
                             "tls.crt": server_certificate,
                             "fixture-mfa-realm.json": realm_payload}}
    created = subprocess.run(provider.kubectl(lab, "create", "-f", "-"), input=json.dumps(secret),
                             capture_output=True, text=True, timeout=20, env=lab.env)
    if created.returncode:
        lab.block("Could not create the private serving and bootstrap fixture inputs")
    labels = {"app": provider.NAME}
    container = {
        "name": "idp", "image": image, "imagePullPolicy": "Never",
        "args": ["start-dev", "--import-realm", "--hostname=" + ISSUER.split("/realms/", 1)[0],
                 "--hostname-strict=true", "--http-enabled=false", "--http-host=127.0.0.1",
                 f"--https-port={LOCAL_PORT}",
                 "--https-certificate-file=/fixture-serving/tls.crt",
                 "--https-certificate-key-file=/fixture-serving/tls.key"],
        "env": [
            {"name": "KC_BOOTSTRAP_ADMIN_USERNAME", "value": provider.ADMIN},
            {"name": "KC_BOOTSTRAP_ADMIN_PASSWORD",
             "valueFrom": {"secretKeyRef": {"name": provider.NAME, "key": "admin-password"}}},
        ],
        "ports": [{"containerPort": LOCAL_PORT}],
        "resources": {"requests": {"cpu": "250m", "memory": "384Mi"}, "limits": {"memory": "1Gi"}},
        "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                            "runAsNonRoot": True, "runAsUser": 1000,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "volumeMounts": [
            {"name": "serving", "mountPath": "/fixture-serving", "readOnly": True},
            {"name": "realm-import", "mountPath": "/opt/keycloak/data/import", "readOnly": True},
        ],
    }
    provider.resource(lab, "Deployment", spec={
        "replicas": 1, "selector": {"matchLabels": labels},
        "template": {"metadata": {"labels": labels}, "spec": {
            "nodeName": lab.cluster + "-control-plane", "hostNetwork": True,
            "dnsPolicy": "ClusterFirstWithHostNet", "automountServiceAccountToken": False,
            "containers": [container],
            "volumes": [
                {"name": "serving", "secret": {"secretName": provider.NAME,
                 "items": [{"key": name, "path": name} for name in ("tls.crt", "tls.key")]}},
                {"name": "realm-import", "secret": {"secretName": provider.NAME,
                 "items": [{"key": "fixture-mfa-realm.json", "path": "fixture-mfa-realm.json"}]}}
            ],
        }},
    })
    # The listener intentionally binds node loopback. Kubelet HTTP probes target the
    # Pod IP, so readiness is verified from the runner through the owned port-forward.
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Running",
                "pod", "-l", f"app={provider.NAME}", "--timeout=110s", timeout=120)
    return ssl.create_default_context(cafile=str(ca_cert)), ca_cert


def wait_node_issuer(lab, pod_name, ca_cert):
    node = lab.cluster + "-control-plane"
    public_ca = "/etc/kubernetes/pki/saf-0405-012-listener-ca.crt"
    lab.command("docker", "cp", str(ca_cert), f"{node}:{public_ca}")
    discovery = ISSUER + "/.well-known/openid-configuration"
    deadline = time.monotonic() + 110
    try:
        while time.monotonic() < deadline:
            # Starting a port-forward probe too early can terminate that tunnel on refusal.
            result = subprocess.run(("docker", "exec", node, "curl", "--noproxy", "*",
                                     "--max-time", "3", "--silent", "--fail", "--cacert", public_ca,
                                     discovery), env=lab.env, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                metadata = json.loads(result.stdout)
                if metadata.get("issuer") != ISSUER:
                    lab.block("The live fixture discovery document advertised an unexpected issuer")
                return
            pod = json.loads(lab.kubectl("get", "pod", pod_name, "-o", "json").stdout)
            status = pod.get("status", {}).get("containerStatuses", [])
            if any(c.get("restartCount", 0) >= 2 and not c.get("ready") for c in status):
                lab.block("The owned provider repeatedly stopped before serving the fixture issuer")
            time.sleep(1)
        lab.block("CA-verified issuer discovery timed out inside the owned Kind node")
    finally:
        lab.command("docker", "exec", node, "rm", "-f", public_ca, timeout=10)


@contextmanager
def forward_tls(lab, provider, pod_name):
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", LOCAL_PORT))
        except OSError:
            lab.block("The fixed local OIDC port is busy; serialize this fixture and retry")
    command = provider.kubectl(lab, "port-forward", "--address", "127.0.0.1",
                               f"pod/{pod_name}", f"{LOCAL_PORT}:{LOCAL_PORT}")
    with subprocess.Popen(command, env=lab.env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True) as process:
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                if not ready.select(12):
                    lab.block("The owned TLS port-forward did not start")
                line = process.stdout.readline().strip()
            if line != f"Forwarding from 127.0.0.1:{LOCAL_PORT} -> {LOCAL_PORT}":
                lab.block("The owned TLS port-forward did not bind to loopback")
            yield f"https://127.0.0.1:{LOCAL_PORT}", process
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
    trust, ca_cert = install_tls(lab, provider, admin, password)
    pods = lab.kubectl("get", "pods", "-l", f"app={provider.NAME}", "-o", "json")
    try:
        pod_rows = json.loads(pods.stdout).get("items", [])
    except (ValueError, json.JSONDecodeError):
        lab.block("Could not inspect the case-owned identity-provider Pod")
    running = [row for row in pod_rows if row.get("status", {}).get("phase") == "Running"]
    if len(running) != 1 or not running[0].get("metadata", {}).get("name"):
        lab.block("The case-owned identity-provider Pod was not uniquely Running")
    pod_name = running[0]["metadata"]["name"]
    wait_node_issuer(lab, pod_name, ca_cert)
    with forward_tls(lab, provider, pod_name) as (endpoint, forward):
        idp = provider.Idp(endpoint)
        idp.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=trust), NoRedirect())
        deadline = time.monotonic() + 18
        last_reason = "no valid discovery response"
        while time.monotonic() < deadline:
            if forward.poll() is not None:
                lab.block("The owned loopback Kubernetes port-forward terminated before discovery")
            try:
                ready_status, ready = idp.request(
                    f"/realms/{REALM}/.well-known/openid-configuration")
            except (OSError, ValueError) as error:
                last_reason = type(error).__name__
            else:
                if ready_status == 200 and ready.get("issuer") == ISSUER:
                    break
                last_reason = "unexpected discovery status or issuer"
            time.sleep(1)
        else:
            lab.block("CA-verified issuer discovery through the owned tunnel timed out: " + last_reason)
        subject_id = setup(lab, idp, provider, admin, password)
        credentials = audit(lab, idp, trust, subject_id, password)
        bridge_spec = importlib.util.spec_from_file_location(
            "saf_0405_012_kubernetes_bridge", HERE / "kubernetes_bridge.py")
        bridge = importlib.util.module_from_spec(bridge_spec)
        bridge_spec.loader.exec_module(bridge)
        bridge.run_bridge(lab, idp, credentials, subject_id, ca_cert)
