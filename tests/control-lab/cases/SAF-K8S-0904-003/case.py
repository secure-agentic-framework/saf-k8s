"""Exercise workspace isolation and bounded Kubernetes workspace identities."""
import json
import hashlib
import http.cookiejar
import os
import re
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


CONTROL_ID = "SAF-K8S-0904-003"
IMAGE = "quay.io/jupyter/base-notebook:2025-04-01@sha256:18691156c62dd82b69951329ee000fa0ca76f1bea6c105ac92c5754a8d92b828"
NAMESPACE = "saf-test"
SCOPE = (
    "One fresh Kind v1.36.1 cluster, two pinned upstream Jupyter base-notebook Pods, and two "
    "case-owned benign dataset endpoints. The notebook Pods have distinct non-root UIDs and "
    "tokenless service accounts, configured CPU/RAM bounds and restrictive security contexts. "
    "Native NetworkPolicy limits each to its labeled endpoint, and native admission enforces "
    "the approved image reference. Each real Jupyter kernel executes a fixed harmless cell "
    "after policy is active. The pinned synthetic Hub also authenticates two fixture users, "
    "spawns their actual KubeSpawner Pods, and applies per-user egress policy to those Pods. "
    "Production identity/session lifecycle, extension governance, full image provenance, "
    "durable storage, real dataset authorization/audit, and deployed controls require separate evidence."
    " An additional check reads the mounted terminal-interface setting and exact "
    "runtime package version, then compares authenticated status and terminal "
    "collection GET responses from both synthetic users. Another additive check compares "
    "two inert server extensions under baseline and restricted mounted configuration; "
    "review approval, provenance, user-installed code restrictions, and durable audit remain adopter evidence."
)

ROOT = Path(__file__).resolve().parent

HUB_RELEASE = "saf-jhub"
HUB_USER = "saf-fixture-user"
HUB_ALICE = "saf-workspace-alice"
HUB_BOB = "saf-workspace-bob"
HUB_USER_SA = "saf-hub-user"
HUB_SECRET = "saf-hub-password"
HUB_PROBE_SCRIPT = "hub-auth-probe.py"
HUB_WORKSPACE_SCRIPT = "hub-workspace-matrix.py"
HUB_ROUTE_SCRIPT = "hub-route-probe.py"
APPROVED_EXTENSION_SOURCE = '''import json
from jupyter_server.base.handlers import JupyterHandler
from tornado import web

FIXTURE_VERSION = "1.0.0"
FIXTURE_MARKER = "saf-approved-extension-v1"

class Handler(JupyterHandler):
    @web.authenticated
    def get(self):
        self.set_header("Content-Type", "application/json")
        self.finish(json.dumps({"extension": "approved", "version": FIXTURE_VERSION,
                                "marker": FIXTURE_MARKER}, sort_keys=True))

def _jupyter_server_extension_points():
    return [{"module": "saf_approved_extension"}]

def _load_jupyter_server_extension(serverapp):
    serverapp.web_app.add_handlers(".*$", [
        (serverapp.base_url.rstrip("/") + "/saf-fixture/approved", Handler)
    ])
'''
UNAPPROVED_EXTENSION_SOURCE = '''import json
from jupyter_server.base.handlers import JupyterHandler
from tornado import web

FIXTURE_VERSION = "1.0.0"
FIXTURE_MARKER = "saf-unapproved-extension-v1"

class Handler(JupyterHandler):
    @web.authenticated
    def get(self):
        self.set_header("Content-Type", "application/json")
        self.finish(json.dumps({"extension": "unapproved", "version": FIXTURE_VERSION,
                                "marker": FIXTURE_MARKER}, sort_keys=True))

def _jupyter_server_extension_points():
    return [{"module": "saf_unapproved_extension"}]

def _load_jupyter_server_extension(serverapp):
    serverapp.web_app.add_handlers(".*$", [
        (serverapp.base_url.rstrip("/") + "/saf-fixture/unapproved", Handler)
    ])
'''
HUB_EXTENSION_CONFIG = (
    "import os, sys\n"
    "sys.path.insert(0, '/opt/saf-jupyter-extensions')\n"
    "c.ServerApp.terminals_enabled = False\n"
    "c.ServerApp.jpserver_extensions.update({\n"
    "    'saf_approved_extension': True,\n"
    "    'saf_unapproved_extension': os.environ.get('JUPYTERHUB_USER') == 'saf-workspace-alice',\n"
    "})\n"
)
CHART = ROOT / "vendor" / "jupyterhub-4.4.5.tgz"
CHART_SHA256 = "27ad182c708244537f425a7ec3354d1a098776e7acd96b7f0d9a4d38f0cda415"
HUB_IMAGE = "quay.io/jupyterhub/k8s-hub:4.4.5@sha256:6ce210488f5598e2dd5130d82e84d9f74b72538b66895861240bd84926ec50bd"
PROXY_IMAGE = "quay.io/jupyterhub/configurable-http-proxy:5.4.0@sha256:7977d796d372642aa9eb962ff36590b3019f8f24493fcf9f1d07d2c81e8e6080"
SINGLEUSER_IMAGE = "quay.io/jupyterhub/k8s-singleuser-sample:4.4.5@sha256:2a05d2f69486f5087b75168da60946891490c788626141b39334d67cae5f97aa"
HUB_SERVICE = f"proxy-public.{NAMESPACE}.svc.cluster.local"


def pod_json(lab, name):
    return json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)


def wait_ready(lab, name, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pod = pod_json(lab, name)
        if pod.get("status", {}).get("phase") == "Running" and any(
            condition.get("type") == "Ready" and condition.get("status") == "True"
            for condition in pod.get("status", {}).get("conditions", [])
        ):
            return pod
        time.sleep(1)
    lab.block(f"Fixture Pod did not become Ready: {name}")


def probe(lab, source, destination, *, interpreter="/opt/conda/bin/python"):
    address = pod_json(lab, destination)["status"]["podIP"]
    script = """
import http.client
import sys
connection = http.client.HTTPConnection(sys.argv[1], port=8080, timeout=1.5)
try:
    connection.request("GET", "/")
    response = connection.getresponse()
    if response.status != 200:
        raise RuntimeError("unexpected response from the owned fixture")
    print("ALLOW:" + response.read().decode())
except TimeoutError:
    print("BLOCKED")
finally:
    connection.close()
"""
    result = lab.kubectl("exec", source, "--", interpreter, "-B",
                         "-c", script, address, timeout=8)
    value = result.stdout.strip()
    if value != "BLOCKED" and not value.startswith("ALLOW:"):
        lab.block(f"Unexpected fixture observation from {source}")
    return value


def run(lab):
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf.example/image-policy=enabled", "--overwrite")
    lab.apply(ROOT / "case" / "workspaces.yaml")
    pods = {}
    for name in ("dataset-alice", "dataset-bob", "workspace-alice", "workspace-bob"):
        pods[name] = wait_ready(lab, name)

    lab.check(
        "positive", "workspace pods have separate non-token service accounts and bounded hardened containers",
        pods["workspace-alice"]["spec"].get("serviceAccountName") == "workspace-alice"
        and pods["workspace-bob"]["spec"].get("serviceAccountName") == "workspace-bob"
        and pods["workspace-alice"]["spec"].get("automountServiceAccountToken") is False
        and pods["workspace-bob"]["spec"].get("automountServiceAccountToken") is False
        and all(_hardened(pods[name]) for name in ("workspace-alice", "workspace-bob")),
        "distinct service accounts; token automount disabled; non-root, seccomp, no escalation, dropped capabilities, read-only root, bounded CPU/memory",
    )

    red_alice = probe(lab, "workspace-alice", "dataset-bob")
    red_bob = probe(lab, "workspace-bob", "dataset-alice")
    if red_alice != "ALLOW:benign-dataset-bob" or red_bob != "ALLOW:benign-dataset-alice":
        lab.block("Baseline cross-workspace probe did not reach the benign endpoint; NetworkPolicy enforcement is not established")
    lab.check("red", "without workspace egress policies, cross-workspace dataset paths are reachable",
              red_alice == "ALLOW:benign-dataset-bob" and red_bob == "ALLOW:benign-dataset-alice",
              "alice-to-bob=ALLOW; bob-to-alice=ALLOW")

    lab.apply(ROOT / "case" / "workspace-egress.yaml")
    expected = {"alice-to-alice": "ALLOW:benign-dataset-alice", "alice-to-bob": "BLOCKED",
                "bob-to-bob": "ALLOW:benign-dataset-bob", "bob-to-alice": "BLOCKED"}
    deadline = time.monotonic() + 35
    observed = {}
    streak = 0
    while time.monotonic() < deadline:
        observed = {f"{source}-to-{destination}": probe(
            lab, f"workspace-{source}", f"dataset-{destination}")
            for source, destination in (("alice", "alice"), ("alice", "bob"), ("bob", "bob"), ("bob", "alice"))}
        streak = streak + 1 if observed == expected else 0
        if streak == 2:
            break
    lab.check("green", "Each workspace reaches its own dataset while both cross-workspace paths remain blocked",
              streak == 2, {**observed, "consecutive_matches": streak})

    unapproved = _dry_run_pod("admission-unapproved", "quay.io/jupyter/base-notebook:2025-04-01")
    baseline = lab.create(unapproved, dry_run=True, allow_failure=True)
    if baseline.returncode:
        lab.block(f"The unapproved-image baseline did not reach Pod admission: {baseline.stderr}")
    lab.check("red", "Without the image binding the same unpinned fixture image is admitted by server dry-run",
              baseline.returncode == 0, {"server_dry_run_admitted": True})
    lab.apply(ROOT / "case" / "image-admission.yaml")
    end = time.monotonic() + 15
    message = "workspace Pod image must match the approved digest-pinned base image"
    while True:
        denied = lab.create(unapproved, dry_run=True, allow_failure=True)
        if denied.returncode or time.monotonic() >= end:
            break
        time.sleep(0.25)
    if denied.returncode and message not in denied.stderr:
        lab.block(f"Image approval probe was rejected by an unrelated response: {denied.stderr}")
    lab.check("green", "The native image policy rejects the same unpinned reference",
              denied.returncode != 0 and message in denied.stderr,
              {"denied_by_policy": denied.returncode != 0, "policy": "saf-notebook-approved-image"})
    accepted = lab.create(_dry_run_pod("admission-approved", IMAGE), dry_run=True, allow_failure=True)
    if accepted.returncode:
        lab.block(f"The pinned positive-control image was not admitted: {accepted.stderr}")
    lab.check("positive", "The exact approved notebook image remains admissible",
              accepted.returncode == 0, {"approved_reference": IMAGE, "admitted": True})

    kernel_script = (ROOT / "notebook-kernel.py").read_text()
    summaries = {}
    for user, uid in (("alice", 1000), ("bob", 1001)):
        result = lab.kubectl("exec", "-i", f"workspace-{user}", "--", "/opt/conda/bin/python", "-B", "-",
                             payload=kernel_script, timeout=55)
        summaries[user] = json.loads(result.stdout)
        spec = pod_json(lab, f"workspace-{user}")["spec"]
        lab.check("positive", f"The {user} workspace executes a fixed cell through its installed Jupyter kernel",
                  summaries[user] == {"uid": uid, "stdout": "fixture-notebook-ok\n", "kernel": "python3"}
                  and spec["containers"][0]["image"] == IMAGE, summaries[user])
    (lab.evidence / "workspace-isolation.raw.json").write_text(json.dumps(
        {"pods": pods, "dataset_access": observed, "kernels": summaries}, indent=2) + "\n")

    _exercise_hub_identity(lab)


def _hardened(pod):
    spec = pod["spec"]
    pod_security = spec.get("securityContext", {})
    if not pod_security.get("runAsNonRoot") or pod_security.get("seccompProfile", {}).get("type") != "RuntimeDefault":
        return False
    containers = spec.get("containers", [])
    if len(containers) != 1:
        return False
    container = containers[0]
    security = container.get("securityContext", {})
    resources = container.get("resources", {})
    return (
        security.get("allowPrivilegeEscalation") is False
        and security.get("readOnlyRootFilesystem") is True
        and "ALL" in security.get("capabilities", {}).get("drop", [])
        and bool(resources.get("requests", {}).get("cpu"))
        and bool(resources.get("requests", {}).get("memory"))
        and bool(resources.get("limits", {}).get("cpu"))
        and bool(resources.get("limits", {}).get("memory"))
    )


def _dry_run_pod(name, image):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {"saf.example/workspace": "true"}},
        "spec": {"containers": [{"name": "workspace", "image": image,
                                  "command": ["python", "-c", "pass"]}]},
    }


def _hub_probe_source():
    # Runs inside a tokenless Pod. It emits only booleans and never logs HTML,
    # headers, cookies, form values, exception messages, or response bodies.
    source = r'''import http.cookiejar, json, os, time, urllib.error, urllib.parse, urllib.request

BASE = "http://proxy-public.saf-test.svc.cluster.local"
USER = "saf-fixture-user"
MODE = os.environ["MODE"]

class HiddenFields(__import__("html.parser", fromlist=["HTMLParser"]).HTMLParser):
    def __init__(self):
        super().__init__(); self.values = {}
    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "input" and fields.get("type") == "hidden" and fields.get("name"):
            self.values[fields["name"]] = fields.get("value", "")

jar = http.cookiejar.CookieJar()
class OwnedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlparse(urllib.parse.urljoin(req.full_url, newurl))
        if target.scheme != "http" or target.netloc != urllib.parse.urlparse(BASE).netloc:
            raise urllib.error.URLError("redirect outside the owned ClusterIP service")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar), OwnedRedirect())
progress = {"phase": "login_form", "status": None}
def request(path, data=None):
    req = urllib.request.Request(BASE + path, data=data, method="POST" if data is not None else "GET")
    try:
        with opener.open(req, timeout=5) as response:
            body = response.read(1048577)
            if len(body) > 1048576:
                raise ValueError("bounded response exceeded")
            progress["status"] = response.status
            return response.status, response.geturl(), body
    except urllib.error.HTTPError as error:
        body = error.read(1048577)
        progress["status"] = error.code
        return error.code, error.geturl(), body

def hidden(body):
    parser = HiddenFields(); parser.feed(body.decode("utf-8", "replace")); return parser.values

def main():
    status, _, body = request("/hub/login")
    if status != 200:
        raise ValueError("login form unavailable")
    fields = hidden(body)
    xsrf = fields.get("_xsrf")
    if not xsrf:
        raise ValueError("login form has no xsrf field")
    password = open("/run/saf-auth/password", encoding="utf-8").read().strip()
    submitted = password if MODE == "allow" else "invalid-fixture-password"
    form = urllib.parse.urlencode({"_xsrf": xsrf, "username": USER, "password": submitted, "next": "/hub/"}).encode()
    progress["phase"] = "login_submit"
    status, final_url, body = request("/hub/login", form)
    if MODE == "deny":
        refusal = (status == 403 and urllib.parse.urlparse(final_url).path == "/hub/login"
                   and b"Invalid username or password" in body)
        print(json.dumps({"mode": "deny", "login_refused": refusal, "login_status": status,
                          "session_cookie_absent": not any(c.name == "jupyterhub-session-id" for c in jar)}))
        return
    progress["phase"] = "session_check"
    if not any(c.name == "jupyterhub-session-id" for c in jar):
        raise ValueError("authenticated session was not established")
    # GET the native spawn page, then submit its XSRF field to the native spawn handler.
    progress["phase"] = "spawn_page"
    status, _, body = request("/hub/spawn")
    if status not in (200, 202, 424):
        raise ValueError("spawn page unavailable")
    xsrf = next((c.value for c in jar if c.name == "_xsrf"), None)
    if not xsrf:
        raise ValueError("authenticated xsrf cookie absent")
    spawn = urllib.parse.urlencode({"_xsrf": xsrf}).encode()
    progress["phase"] = "spawn_submit"
    request("/hub/spawn", spawn)
    progress["phase"] = "spawned_route"
    deadline = time.monotonic() + 180
    routed = False
    while time.monotonic() < deadline:
        try:
            status, final_url, _ = request("/user/" + USER + "/")
            if status == 200 and "/user/" + USER + "/" in final_url:
                routed = True; break
        except (OSError, TimeoutError, urllib.error.URLError):
            pass
        time.sleep(1)
    print(json.dumps({"mode": "allow", "authenticated_cookie_seen": True,
                      "spawned_server_route_ok": routed}))

try:
    main()
except Exception as exc:
    print(json.dumps({"mode": MODE, "completed": False, "failure_type": type(exc).__name__, **progress}))
    raise SystemExit(1)
'''
    return source.replace("http://proxy-public.saf-test.svc.cluster.local", "http://" + HUB_SERVICE)


def _hub_values():
    return {
        "hub": {
            "image": {"name": "quay.io/jupyterhub/k8s-hub",
                      "tag": "4.4.5@sha256:6ce210488f5598e2dd5130d82e84d9f74b72538b66895861240bd84926ec50bd"},
            "config": {
                "JupyterHub": {"authenticator_class": "shared-password", "admin_access": False},
                "Authenticator": {"allow_all": False, "allowed_users": [HUB_USER, HUB_ALICE, HUB_BOB], "admin_users": []},
            },
            "extraConfig": {
                "00-read-fixture-password.py": (
                    "from pathlib import Path\n"
                    "c.SharedPasswordAuthenticator.user_password = Path('/run/saf-auth/password').read_text().strip()\n"
                )
            },
            "extraVolumes": [{"name": "fixture-auth", "secret": {
                "secretName": HUB_SECRET, "defaultMode": 0o440}}],
            "extraVolumeMounts": [{"name": "fixture-auth", "mountPath": "/run/saf-auth", "readOnly": True}],
            "db": {"type": "sqlite-memory"},
            "resources": {"requests": {"cpu": "100m", "memory": "256Mi"},
                          "limits": {"cpu": "500m", "memory": "768Mi"}},
        },
        "proxy": {
            "service": {"type": "ClusterIP"},
            "chp": {"image": {"name": "quay.io/jupyterhub/configurable-http-proxy",
                               "tag": "5.4.0@sha256:7977d796d372642aa9eb962ff36590b3019f8f24493fcf9f1d07d2c81e8e6080"},
                    "resources": {"requests": {"cpu": "50m", "memory": "96Mi"},
                                  "limits": {"cpu": "250m", "memory": "256Mi"}}},
        },
        "singleuser": {
            "image": {"name": "quay.io/jupyterhub/k8s-singleuser-sample",
                      "tag": "4.4.5@sha256:2a05d2f69486f5087b75168da60946891490c788626141b39334d67cae5f97aa",
                      "pullPolicy": "IfNotPresent"},
            "serviceAccountName": HUB_USER_SA,
            "storage": {"type": "none"},
            "extraFiles": {
                "saf-terminals-disabled.py": {
                    "mountPath": "/etc/jupyter/jupyter_server_config.py",
                    "stringData": HUB_EXTENSION_CONFIG,
                },
                "saf-approved-extension.py": {
                    "mountPath": "/opt/saf-jupyter-extensions/saf_approved_extension.py",
                    "stringData": APPROVED_EXTENSION_SOURCE,
                },
                "saf-unapproved-extension.py": {
                    "mountPath": "/opt/saf-jupyter-extensions/saf_unapproved_extension.py",
                    "stringData": UNAPPROVED_EXTENSION_SOURCE,
                },
            },
            "networkPolicy": {
                "enabled": True,
                "egress": [],
                "egressAllowRules": {
                    "cloudMetadataServer": False,
                    "dnsPortsCloudMetadataServer": False,
                    "dnsPortsKubeSystemNamespace": True,
                    "dnsPortsPrivateIPs": False,
                    "nonPrivateIPs": False,
                    "privateIPs": False,
                },
            },
            "cloudMetadata": {"blockWithIptables": False},
            "extraPodConfig": {"automountServiceAccountToken": False},
            "extraLabels": {"saf.example/workspace": "hub-spawned"},
            "cpu": {"guarantee": 0.1, "limit": 0.5},
            "memory": {"guarantee": "256M", "limit": "768M"},
            "startTimeout": 180,
        },
        "scheduling": {"userScheduler": {"enabled": False}},
        "prePuller": {"hook": {"enabled": False}, "continuous": {"enabled": False}},
        "ingress": {"enabled": False},
    }


def _create_password_secret(lab, password):
    # Never pass secret bytes through Lab.command's stdin logging. The exact
    # create manifest exists only in a private temporary directory and is
    # unlinked as soon as the API has accepted it.
    with tempfile.TemporaryDirectory(prefix="saf-hub-secret-") as directory:
        os.chmod(directory, 0o700)
        path = Path(directory) / "secret.json"
        document = {
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": HUB_SECRET, "namespace": NAMESPACE,
                         "labels": {"saf.example/fixture": "hub-auth"}},
            "type": "Opaque", "immutable": True,
            "data": {"password": __import__("base64").b64encode(password.encode()).decode()},
        }
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump(document, output)
        lab.kubectl("create", "-f", str(path), "-o", "name")
        path.unlink()


def _helm_args(lab):
    return ("helm", "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}")


def _render_chart(lab, values_path):
    if not CHART.is_file() or hashlib.sha256(CHART.read_bytes()).hexdigest() != CHART_SHA256:
        lab.block("The vendored official JupyterHub chart archive digest does not match its reviewed pin")
    try:
        rendered = subprocess.run(
            [*_helm_args(lab), "template", HUB_RELEASE, str(CHART), "--namespace", NAMESPACE,
             "--values", str(values_path)], env=lab.env, text=True,
            capture_output=True, timeout=45, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        lab.block("The bounded offline Helm template preflight could not run")
    if rendered.returncode:
        lab.block("The offline Helm template preflight rejected the reviewed chart values")
    text = rendered.stdout
    values_match = re.search(r'(?m)^  values\.yaml: "([A-Za-z0-9+/=]+)"$', text)
    try:
        decoded_values = __import__("base64").b64decode(values_match.group(1), validate=True).decode() if values_match else ""
    except (ValueError, UnicodeDecodeError):
        decoded_values = ""
    required = ("type: ClusterIP", HUB_IMAGE, PROXY_IMAGE, "  name: proxy-public")
    effective_singleuser = (
        "name: quay.io/jupyterhub/k8s-singleuser-sample" in decoded_values
        and "tag: 4.4.5@sha256:2a05d2f69486f5087b75168da60946891490c788626141b39334d67cae5f97aa" in decoded_values
        and f"serviceAccountName: {HUB_USER_SA}" in decoded_values
    )
    if not all(item in text for item in required) or not effective_singleuser or "type: LoadBalancer" in text:
        lab.block("Rendered Hub resources do not match the reviewed service and image pins")
    # Never persist or print rendered templates: they include generated secret material.


def _run_job(lab, name, mode):
    resource = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {"saf.example/fixture": "hub-auth"}},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 210,
                 "template": {"metadata": {"labels": {"saf.example/fixture": "hub-auth"}},
                              "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                       "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                                           "fsGroup": 100,
                                                           "runAsGroup": 100, "seccompProfile": {"type": "RuntimeDefault"}},
                                       "containers": [{"name": "probe", "image": SINGLEUSER_IMAGE,
                                                       "imagePullPolicy": "IfNotPresent",
                                                       "command": ["python", "-B", "/opt/saf/hub-auth-probe.py"],
                                                       "env": [{"name": "MODE", "value": mode}],
                                                       "volumeMounts": [
                                                           {"name": "script", "mountPath": "/opt/saf", "readOnly": True},
                                                           {"name": "auth", "mountPath": "/run/saf-auth", "readOnly": True}],
                                                       "resources": {"requests": {"cpu": "25m", "memory": "64Mi"},
                                                                     "limits": {"cpu": "100m", "memory": "192Mi"}}}],
                                       "volumes": [{"name": "script", "configMap": {"name": "saf-hub-probe"}},
                                                   {"name": "auth", "secret": {"secretName": HUB_SECRET,
                                                                                 "defaultMode": 0o440}}]}}},
    }
    lab.create(resource)
    deadline = time.monotonic() + 220
    terminal = set()
    while time.monotonic() < deadline:
        statuses = lab.kubectl(
            "get", "job", name, "-o",
            'jsonpath={range .status.conditions[?(@.status=="True")]}{.type}{"\\n"}{end}',
            timeout=12,
        ).stdout
        terminal = set(statuses.split())
        if terminal & {"Complete", "Failed"}:
            break
        time.sleep(1)
    log = lab.kubectl("logs", f"job/{name}", allow_failure=True, timeout=15).stdout.strip()
    try:
        result = json.loads(log)
    except json.JSONDecodeError:
        lab.block("The Hub probe returned no stable JSON outcome")
    if "Complete" not in terminal or result.get("mode") != mode or result.get("completed") is False:
        phase = result.get("phase")
        status = result.get("status")
        lab.block(f"The Hub probe did not complete: mode={mode}, phase={phase}, HTTP status={status}")
    return result


def _hub_workspace_matrix_source():
    # Separate cookie jars model two independently authenticated usernames.
    # The fixture-only SharedPasswordAuthenticator has one temporary shared
    # password, so this does not claim distinct user passwords or IdP behavior.
    return r'''import http.cookiejar, json, os, time, urllib.error, urllib.parse, urllib.request

BASE = "http://proxy-public.saf-test.svc.cluster.local"
PASSWORD = open("/run/saf-auth/password", encoding="utf-8").read().strip()
USERS = ("saf-workspace-alice", "saf-workspace-bob")
MARKERS = {USERS[0]: "workspace-marker-alice", USERS[1]: "workspace-marker-bob"}
progress = {}

class Fields(__import__("html.parser", fromlist=["HTMLParser"]).HTMLParser):
    def __init__(self): super().__init__(); self.values = {}
    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "input" and fields.get("type") == "hidden" and fields.get("name"):
            self.values[fields["name"]] = fields.get("value", "")

class SameServiceRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlparse(urllib.parse.urljoin(req.full_url, newurl))
        if target.scheme != "http" or target.netloc != urllib.parse.urlparse(BASE).netloc:
            raise urllib.error.URLError("redirect outside owned service")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def new_session():
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(jar), SameServiceRedirect())
    return jar, opener

def request(opener, path, method="GET", payload=None, xsrf=None, content_type=None, referer=None):
    headers = {}
    if payload is not None:
        headers["Content-Type"] = content_type or "application/x-www-form-urlencoded"
    if xsrf: headers["X-XSRFToken"] = xsrf
    if referer: headers["Referer"] = referer
    req = urllib.request.Request(BASE + path, data=payload, method=method, headers=headers)
    try:
        with opener.open(req, timeout=5) as response:
            body = response.read(262145)
            if len(body) > 262144: raise ValueError("bounded response exceeded")
            return response.status, response.geturl(), body
    except urllib.error.HTTPError as error:
        body = error.read(262145)
        return error.code, error.geturl(), body

def xsrf_for_path(jar, path):
    matches = [cookie for cookie in jar if cookie.name == "_xsrf" and path.startswith(cookie.path)]
    return max(matches, key=lambda cookie: len(cookie.path)).value if matches else None

def login_and_spawn(username):
    progress.update(phase="login", identity=username)
    jar, opener = new_session()
    status, _, body = request(opener, "/hub/login")
    if status != 200: raise ValueError("login form unavailable")
    parser = Fields(); parser.feed(body.decode("utf-8", "replace"))
    xsrf = parser.values.get("_xsrf")
    if not xsrf: raise ValueError("login xsrf unavailable")
    fields = urllib.parse.urlencode({"_xsrf": xsrf, "username": username,
                                     "password": PASSWORD, "next": "/hub/"}).encode()
    status, _, _ = request(opener, "/hub/login", "POST", fields)
    if not any(c.name == "jupyterhub-session-id" for c in jar):
        raise ValueError("synthetic login did not establish a session")
    xsrf = xsrf_for_path(jar, "/hub/spawn")
    if not xsrf: raise ValueError("session xsrf cookie unavailable")
    progress["phase"] = "spawn"
    status, _, _ = request(opener, "/hub/spawn")
    if status not in (200, 202, 424): raise ValueError("spawn page unavailable")
    request(opener, "/hub/spawn", "POST", urllib.parse.urlencode({"_xsrf": xsrf}).encode())
    deadline = time.monotonic() + 180
    routed = False
    while time.monotonic() < deadline:
        try:
            status, final, _ = request(opener, "/user/" + username + "/")
            if status == 200 and urllib.parse.urlparse(final).path.startswith("/user/" + username + "/"):
                routed = True; break
        except (OSError, TimeoutError, urllib.error.URLError): pass
        time.sleep(1)
    if not routed: raise ValueError("owned server route did not become ready")
    return jar, opener

def main():
    sessions = {user: login_and_spawn(user) for user in USERS}
    own_read = {}
    extension_matrix = {}
    for user in USERS:
        jar, opener = sessions[user]
        progress.update(phase="own_marker", identity=user)
        path = "/user/" + user + "/api/contents/saf-fixture-workspace.txt?content=1&format=text"
        document = json.dumps({"path": "saf-fixture-workspace.txt", "type": "file",
                               "format": "text", "content": MARKERS[user]}).encode()
        referer = BASE + "/user/" + user + "/"
        request(opener, path, referer=referer)
        xsrf = xsrf_for_path(jar, path.split("?", 1)[0])
        if not xsrf: raise ValueError("notebook xsrf token unavailable")
        status, _, _ = request(opener, path, "PUT", document, xsrf, "application/json", referer)
        progress["status"] = status
        if status not in (200, 201): raise ValueError("owned marker write refused")
        status, _, body = request(opener, path, referer=referer)
        try: model = json.loads(body)
        except (ValueError, UnicodeDecodeError): model = {}
        own_read[user] = status == 200 and model.get("content") == MARKERS[user]
        # Read-only endpoints only: never POST /api/terminals or request a shell.
        status_server, _, _ = request(opener, "/user/" + user + "/api/status")
        status_terminals, _, _ = request(opener, "/user/" + user + "/api/terminals")
        progress.setdefault("server_api", {})[user] = {
            "authenticated_status_ok": status_server == 200,
            "terminals_endpoint_status": status_terminals,
        }
        extension_matrix[user] = {}
        for extension in ("approved", "unapproved"):
            try:
                status_extension, _, extension_body = request(
                    opener, "/user/" + user + "/saf-fixture/" + extension,
                    referer=BASE + "/user/" + user + "/")
            except (OSError, TimeoutError, urllib.error.URLError, ValueError):
                status_extension, extension_body = 0, b""
            try:
                extension_document = json.loads(extension_body)
            except (ValueError, UnicodeDecodeError):
                extension_document = {}
            extension_matrix[user][extension] = {
                "status": status_extension,
                "marker_matches": extension_document.get("marker") ==
                    "saf-" + ("approved" if extension == "approved" else "unapproved") + "-extension-v1",
                "version": extension_document.get("version", ""),
            }
    cross_denied = {}
    for reader, owner in ((USERS[0], USERS[1]), (USERS[1], USERS[0])):
        _, opener = sessions[reader]
        path = "/user/" + owner + "/api/contents/saf-fixture-workspace.txt?content=1&format=text"
        status, _, _ = request(opener, path, referer=BASE + "/user/" + reader + "/")
        cross_denied[reader + "_to_" + owner] = status == 403
    print(json.dumps({"own_marker_read": own_read, "cross_user_forbidden": cross_denied,
                      "separate_authenticated_sessions": len(sessions) == 2,
                      "server_api": progress.get("server_api", {}),
                      "extension_matrix": extension_matrix}, sort_keys=True))

try:
    main()
except Exception as exc:
    # Exception messages and HTTP bodies can contain cookies or submitted data.
    print(json.dumps({"completed": False, "failure_type": type(exc).__name__, **progress}))
    raise SystemExit(1)
'''.replace("http://proxy-public.saf-test.svc.cluster.local", "http://" + HUB_SERVICE)


def _hub_route_probe_source():
    # This post-policy in-cluster client records only route booleans. It never
    # emits the shared fixture password, cookies, headers, HTML, or response data.
    return r'''import http.cookiejar, json, os, time, urllib.error, urllib.parse, urllib.request

BASE = "http://proxy-public.saf-test.svc.cluster.local"
USERS = ("saf-workspace-alice", "saf-workspace-bob")
PASSWORD = open("/run/saf-auth/password", encoding="utf-8").read().strip()

class Fields(__import__("html.parser", fromlist=["HTMLParser"]).HTMLParser):
    def __init__(self): super().__init__(); self.values = {}
    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "input" and fields.get("name") == "_xsrf":
            self.values["_xsrf"] = fields.get("value", "")

class OwnedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlparse(urllib.parse.urljoin(req.full_url, newurl))
        if target.scheme != "http" or target.netloc != urllib.parse.urlparse(BASE).netloc:
            raise urllib.error.URLError("redirect outside owned Hub service")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def request(opener, path, data=None, xsrf=None):
    headers = {"Content-Type": "application/x-www-form-urlencoded"} if data is not None else {}
    if xsrf:
        headers["X-XSRFToken"] = xsrf
    req = urllib.request.Request(BASE + path, data=data,
        headers=headers)
    try:
        with opener.open(req, timeout=4) as response:
            body = response.read(262145)
            if len(body) > 262144:
                raise ValueError("bounded response exceeded")
            return response.status, response.geturl(), body
    except urllib.error.HTTPError as error:
        body = error.read(262145)
        if len(body) > 262144:
            raise ValueError("bounded error response exceeded")
        return error.code, error.geturl(), body

routes = {}
for username in USERS:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(jar), OwnedRedirect())
    status, _, page = request(opener, "/hub/login")
    if status != 200:
        routes[username] = False
        continue
    parser = Fields(); parser.feed(page.decode("utf-8", "replace"))
    xsrf = parser.values.get("_xsrf")
    if not xsrf:
        routes[username] = False
        continue
    form = urllib.parse.urlencode({"_xsrf": xsrf, "username": username,
                                   "password": PASSWORD, "next": "/hub/"}).encode()
    request(opener, "/hub/login", form)
    session = any(cookie.name == "jupyterhub-session-id" for cookie in jar)
    routes[username] = False
    if not session:
        continue
    xsrf_cookies = [cookie for cookie in jar if cookie.name == "_xsrf"
                    and "/hub/spawn".startswith(cookie.path)]
    spawn_xsrf = max(xsrf_cookies, key=lambda cookie: len(cookie.path)).value if xsrf_cookies else None
    if not spawn_xsrf:
        continue
    request(opener, "/hub/spawn")
    request(opener, "/hub/spawn", urllib.parse.urlencode({"_xsrf": spawn_xsrf}).encode(), spawn_xsrf)
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        try:
            status, final, _ = request(opener, "/user/" + username + "/")
            if status == 200 and urllib.parse.urlparse(final).path.startswith("/user/" + username + "/"):
                routes[username] = True
                break
        except (OSError, TimeoutError, urllib.error.URLError):
            pass
        time.sleep(1)
print(json.dumps({"route_ready": routes}, sort_keys=True, separators=(",", ":")))
'''.replace("http://proxy-public.saf-test.svc.cluster.local", "http://" + HUB_SERVICE)


def _exercise_hub_workspace_matrix(lab):
    job_name = "saf-hub-workspace-matrix"
    resource = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": job_name, "namespace": NAMESPACE,
                     "labels": {"saf.example/fixture": "hub-auth"}},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 390,
                 "template": {"metadata": {"labels": {"saf.example/fixture": "hub-auth"}},
                              "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                       "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                                           "fsGroup": 100, "runAsGroup": 100,
                                                           "seccompProfile": {"type": "RuntimeDefault"}},
                                       "containers": [{"name": "probe", "image": SINGLEUSER_IMAGE,
                                                       "imagePullPolicy": "IfNotPresent",
                                                       "command": ["python", "-B", "/opt/saf/" + HUB_WORKSPACE_SCRIPT],
                                                       "volumeMounts": [
                                                           {"name": "script", "mountPath": "/opt/saf", "readOnly": True},
                                                           {"name": "auth", "mountPath": "/run/saf-auth", "readOnly": True}],
                                                       "resources": {"requests": {"cpu": "25m", "memory": "64Mi"},
                                                                     "limits": {"cpu": "100m", "memory": "192Mi"}}}],
                                       "volumes": [{"name": "script", "configMap": {"name": "saf-hub-probe"}},
                                                   {"name": "auth", "secret": {"secretName": HUB_SECRET,
                                                                                 "defaultMode": 0o440}}]}}}
    }
    lab.create(resource)
    deadline = time.monotonic() + 410
    terminal = set()
    while time.monotonic() < deadline:
        statuses = lab.kubectl("get", "job", job_name, "-o",
            'jsonpath={range .status.conditions[?(@.status=="True")]}{.type}{"\\n"}{end}', timeout=12).stdout
        terminal = set(statuses.split())
        if terminal & {"Complete", "Failed"}: break
        time.sleep(1)
    log = lab.kubectl("logs", f"job/{job_name}", allow_failure=True, timeout=15).stdout.strip()
    try: result = json.loads(log)
    except json.JSONDecodeError: lab.block("Two-user workspace probe returned no stable JSON")
    if "Complete" not in terminal or result.get("completed") is False:
        lab.block("Two-user workspace probe did not complete")
    expected = {user: True for user in (HUB_ALICE, HUB_BOB)}
    cross = {HUB_ALICE + "_to_" + HUB_BOB: True, HUB_BOB + "_to_" + HUB_ALICE: True}
    rows = {user: _hub_user_pods(lab, user) for user in (HUB_ALICE, HUB_BOB)}
    for user in (HUB_ALICE, HUB_BOB):
        lab.kubectl("wait", "--for=condition=Ready", "pod", "-l",
                    f"hub.jupyter.org/username={user}", "--timeout=30s", timeout=40)
        rows[user] = _hub_user_pods(lab, user)
    identities = all(len(rows[user]) == 1 and len(rows[user][0]) == 4
                     and rows[user][0][1] == HUB_USER_SA
                     and rows[user][0][2] == SINGLEUSER_IMAGE
                     and rows[user][0][3] == "Running" for user in (HUB_ALICE, HUB_BOB))
    identities = identities and rows[HUB_ALICE][0][0] != rows[HUB_BOB][0][0]
    passed = (result.get("own_marker_read") == expected
              and result.get("cross_user_forbidden") == cross
              and result.get("separate_authenticated_sessions") is True and identities)
    lab.check("positive", "Two separately authenticated Hub usernames read their own workspace marker and cannot read the other user's marker",
              passed,
              {"separate_authenticated_sessions": result.get("separate_authenticated_sessions") is True,
               "own_marker_read": result.get("own_marker_read"),
               "cross_user_forbidden": result.get("cross_user_forbidden"),
               "distinct_ready_user_pods": identities,
               "two_user_pods_observed": all(len(rows[user]) == 1 for user in (HUB_ALICE, HUB_BOB)),
               "authorization_path": "JupyterHub 5.5.5 single-user server native access scope"})
    (lab.evidence / "hub-workspace-matrix-summary.json").write_text(json.dumps(lab.checks[-1], indent=2) + "\n")
    server_rows = result.get("server_api", {})
    config_mounts = {user: _hub_terminal_config_mount(lab, user) for user in (HUB_ALICE, HUB_BOB)}
    endpoint_statuses = {user: server_rows.get(user, {}).get("terminals_endpoint_status")
                         for user in (HUB_ALICE, HUB_BOB)}
    terminal_gate = (
        all(server_rows.get(user, {}).get("authenticated_status_ok") is True
            and server_rows.get(user, {}).get("terminals_endpoint_status") == 404
            for user in (HUB_ALICE, HUB_BOB))
        and all(isinstance(config_mounts[user], dict) and config_mounts[user].get("mounted_config_ok") is True
                and bool(config_mounts[user].get("jupyter_server_version")) for user in (HUB_ALICE, HUB_BOB))
        and isinstance(config_mounts[HUB_ALICE], dict)
        and config_mounts[HUB_ALICE].get("jupyter_server_version") == config_mounts[HUB_BOB].get("jupyter_server_version")
    )
    lab.check("positive", "Authenticated user servers report status, expose no terminal collection, and carry the exact mounted terminal-disable config",
              terminal_gate,
              {"authenticated_status_ok": all(server_rows.get(user, {}).get("authenticated_status_ok") is True
                                                for user in (HUB_ALICE, HUB_BOB)),
               "jupyter_server_versions_observed": {user: config_mounts[user].get("jupyter_server_version", "")
                                                     if isinstance(config_mounts[user], dict) else ""
                                                     for user in (HUB_ALICE, HUB_BOB)},
               "same_server_version_for_both_users": all(isinstance(config_mounts[user], dict)
                   for user in (HUB_ALICE, HUB_BOB))
                   and config_mounts[HUB_ALICE].get("jupyter_server_version") == config_mounts[HUB_BOB].get("jupyter_server_version"),
               "terminals_get_not_available": all(value == 404 for value in endpoint_statuses.values()),
               "terminal_endpoint_statuses": endpoint_statuses,
               "exact_config_mounted_for_both_users": all(isinstance(config_mounts[user], dict)
                   and config_mounts[user].get("mounted_config_ok") is True for user in (HUB_ALICE, HUB_BOB)),
               "terminal_create_called": False})
    (lab.evidence / "hub-terminal-readonly-summary.json").write_text(json.dumps(lab.checks[-1], indent=2) + "\n")
    extension_rows = result.get("extension_matrix", {})
    extension_mounts = {user: _hub_extension_identity(lab, user) for user in (HUB_ALICE, HUB_BOB)}
    extension_expectations = {
        HUB_ALICE: {"approved": (200, True), "unapproved": (200, True)},
        HUB_BOB: {"approved": (200, True), "unapproved": (404, False)},
    }
    extension_routes_match = all(
        extension_rows.get(user, {}).get(extension, {}).get("status") == expected[0]
        and extension_rows.get(user, {}).get(extension, {}).get("marker_matches") is expected[1]
        and (expected[0] != 200 or extension_rows.get(user, {}).get(extension, {}).get("version") == "1.0.0")
        for user, routes in extension_expectations.items()
        for extension, expected in routes.items())
    extension_identity_match = all(
        extension_mounts[user].get("mounted_files_match") is True
        and extension_mounts[user].get("jupyter_server_version") == "2.21.1"
        and extension_mounts[user].get("approved_version") == "1.0.0"
        and extension_mounts[user].get("unapproved_version") == "1.0.0"
        for user in (HUB_ALICE, HUB_BOB))
    extension_identity_stable = all(
        extension_mounts[user].get("uid_before")
        and extension_mounts[user].get("uid_before") == extension_mounts[user].get("uid_after")
        and extension_mounts[user].get("ready_before") is True
        and extension_mounts[user].get("ready_after") is True
        for user in (HUB_ALICE, HUB_BOB))
    (lab.evidence / "hub-extension-policy.raw.json").write_text(json.dumps({
        "users": {user: {"pod_uid_before": extension_mounts[user].get("uid_before"),
                         "pod_uid_after": extension_mounts[user].get("uid_after"),
                         "mounted": extension_mounts[user],
                         "routes": extension_rows.get(user, {})}
                   for user in (HUB_ALICE, HUB_BOB)},
        "expected": extension_expectations,
    }, indent=2) + "\n")
    lab.check("positive", "Pinned Jupyter Server loads both baseline fixture extensions and only the approved extension under the restricted user policy",
              extension_routes_match and extension_identity_match and extension_identity_stable,
              {"baseline_both_fixture_extensions_callable": (
                   extension_rows.get(HUB_ALICE, {}).get("approved", {}).get("status") == 200
                   and extension_rows.get(HUB_ALICE, {}).get("unapproved", {}).get("status") == 200),
               "restricted_approved_extension_callable": (
                   extension_rows.get(HUB_BOB, {}).get("approved", {}).get("status") == 200),
               "restricted_unapproved_extension_not_available": (
                   extension_rows.get(HUB_BOB, {}).get("unapproved", {}).get("status") == 404),
               "authenticated_route_matrix_matches": extension_routes_match,
               "exact_config_and_module_digests_match": extension_identity_match,
               "pinned_jupyter_server_2_21_1": all(
                   extension_mounts[user].get("jupyter_server_version") == "2.21.1"
                   for user in (HUB_ALICE, HUB_BOB)),
               "same_ready_user_pod_before_and_after": extension_identity_stable,
               "extension_fixture_versions": {"approved": "1.0.0", "unapproved": "1.0.0"},
               "mounted_sha256": {user: extension_mounts[user].get("sha256", {})
                                  for user in (HUB_ALICE, HUB_BOB)}})
    (lab.evidence / "hub-extension-policy-summary.json").write_text(json.dumps(lab.checks[-1], indent=2) + "\n")
    _exercise_hub_spawned_egress(lab)


def _pod_ready(pod):
    return (pod.get("status", {}).get("phase") == "Running"
            and any(condition.get("type") == "Ready" and condition.get("status") == "True"
                    for condition in pod.get("status", {}).get("conditions", [])))


def _owned_hub_user_pods(lab):
    result = json.loads(lab.kubectl("get", "pods", "-l",
        "saf.example/workspace=hub-spawned", "-o", "json").stdout)
    rows = {}
    for user in (HUB_ALICE, HUB_BOB):
        selected = [pod for pod in result.get("items", [])
                    if pod.get("metadata", {}).get("labels", {}).get("hub.jupyter.org/username") == user]
        if (len(selected) != 1 or not selected[0].get("metadata", {}).get("uid")
                or not _pod_ready(selected[0])
                or selected[0].get("spec", {}).get("serviceAccountName") != HUB_USER_SA
                or not any(container.get("image") == SINGLEUSER_IMAGE
                           for container in selected[0].get("spec", {}).get("containers", []))):
            lab.block("Expected one Ready, identity-bound KubeSpawner Pod for each exact synthetic user")
        rows[user] = selected[0]
    if rows[HUB_ALICE]["metadata"]["uid"] == rows[HUB_BOB]["metadata"]["uid"]:
        lab.block("The two synthetic Hub users did not map to distinct Pod UIDs")
    return rows


def _dataset_identity(lab, name, expected_owner):
    pod = pod_json(lab, name)
    labels = pod.get("metadata", {}).get("labels", {})
    address = pod.get("status", {}).get("podIP")
    uid = pod.get("metadata", {}).get("uid")
    if (labels.get("saf.example/dataset-owner") != expected_owner
            or not uid or not address or not _pod_ready(pod)):
        lab.block("The case-owned dataset endpoint identity is not Ready and address-bound")
    return {"pod": name, "uid": uid, "pod_ip": address, "owner": expected_owner}


def _policy_exact(lab, policy_name, username, owner):
    policy = json.loads(lab.kubectl("get", "networkpolicy", policy_name,
                                    "-o", "json").stdout)
    spec = policy.get("spec", {})
    expected_rule = {"to": [{"podSelector": {"matchLabels":
                    {"saf.example/dataset-owner": owner}}}],
                     "ports": [{"protocol": "TCP", "port": 8080}]}
    return (policy.get("metadata", {}).get("namespace") == NAMESPACE
            and policy.get("metadata", {}).get("labels", {}).get("saf.example/fixture") == "hub-spawn-egress"
            and spec.get("podSelector") == {"matchLabels": {"hub.jupyter.org/username": username}}
            and spec.get("policyTypes") == ["Egress"]
            and spec.get("egress") == [expected_rule])


def _run_post_policy_route_probe(lab):
    name = "saf-hub-egress-route-probe"
    resource = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {"saf.example/fixture": "hub-spawn-egress"}},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 150,
                 "template": {"metadata": {"labels": {"saf.example/fixture": "hub-spawn-egress"}},
                              "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                       "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                                           "runAsGroup": 100, "fsGroup": 100,
                                                           "seccompProfile": {"type": "RuntimeDefault"}},
                                       "containers": [{"name": "probe", "image": SINGLEUSER_IMAGE,
                                                       "imagePullPolicy": "IfNotPresent",
                                                       "command": ["python", "-B", "/opt/saf/" + HUB_ROUTE_SCRIPT],
                                                       "volumeMounts": [
                                                           {"name": "script", "mountPath": "/opt/saf", "readOnly": True},
                                                           {"name": "auth", "mountPath": "/run/saf-auth", "readOnly": True}],
                                                       "resources": {"requests": {"cpu": "25m", "memory": "64Mi"},
                                                                     "limits": {"cpu": "100m", "memory": "192Mi"}}}],
                                       "volumes": [{"name": "script", "configMap": {"name": "saf-hub-probe"}},
                                                   {"name": "auth", "secret": {"secretName": HUB_SECRET,
                                                                                 "defaultMode": 0o440}}]}}}
    }
    lab.create(resource)
    deadline = time.monotonic() + 165
    terminal = set()
    while time.monotonic() < deadline:
        statuses = lab.kubectl("get", "job", name, "-o",
            'jsonpath={range .status.conditions[?(@.status=="True")]}{.type}{"\\n"}{end}', timeout=12).stdout
        terminal = set(statuses.split())
        if terminal & {"Complete", "Failed"}:
            break
        time.sleep(1)
    if "Complete" not in terminal:
        lab.block("The bounded post-policy Hub route probe did not complete")
    output = lab.kubectl("logs", "job/" + name, timeout=15).stdout.strip()
    try:
        result = json.loads(output)
    except json.JSONDecodeError:
        lab.block("The bounded post-policy route probe did not return stable JSON booleans")
    return result.get("route_ready") == {HUB_ALICE: True, HUB_BOB: True}


def _exercise_hub_spawned_egress(lab):
    users = {HUB_ALICE: "alice", HUB_BOB: "bob"}
    pods_before = _owned_hub_user_pods(lab)
    endpoints_before = {user: _dataset_identity(lab, "dataset-" + owner, owner)
                        for user, owner in users.items()}
    control_policy = "saf-hub-egress-both-owned-datasets"
    lab.create({
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": control_policy, "namespace": NAMESPACE},
        "spec": {
            "podSelector": {
                "matchLabels": {"saf.example/workspace": "hub-spawned"},
                "matchExpressions": [{"key": "hub.jupyter.org/username", "operator": "In",
                                      "values": [HUB_ALICE, HUB_BOB]}],
            },
            "policyTypes": ["Egress"],
            "egress": [{"to": [{"podSelector": {"matchExpressions": [
                {"key": "saf.example/dataset-owner", "operator": "In", "values": ["alice", "bob"]}
            ]}}], "ports": [{"protocol": "TCP", "port": 8080}]}],
        },
    })
    expected_baseline = {HUB_ALICE + "_to_own": "ALLOW:benign-dataset-alice",
                         HUB_BOB + "_to_own": "ALLOW:benign-dataset-bob",
                         HUB_ALICE + "_to_" + HUB_BOB: "ALLOW:benign-dataset-bob",
                         HUB_BOB + "_to_" + HUB_ALICE: "ALLOW:benign-dataset-alice"}
    def observe_paths():
        return {
            user + "_to_" + (destination if user != destination else "own"): probe(
                lab, pods_before[user]["metadata"]["name"], "dataset-" + owner,
                interpreter="python",
            )
            for user in users
            for destination, owner in users.items()
        }

    baseline = {}
    try:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            baseline = observe_paths()
            if baseline == expected_baseline:
                break
            time.sleep(0.4)
    finally:
        lab.kubectl("delete", "networkpolicy", control_policy, "--wait=true", timeout=30)
    if baseline != expected_baseline:
        lab.block("The temporary owned-dataset allowance did not establish the exact Hub-spawned endpoint baseline")

    lab.apply(ROOT / "case" / "hub-workspace-egress.yaml")
    all_policies = json.loads(lab.kubectl("get", "networkpolicies", "-o", "json").stdout).get("items", [])
    chart_candidates = []
    for candidate in all_policies:
        labels = candidate.get("metadata", {}).get("labels", {})
        selector = candidate.get("spec", {}).get("podSelector", {}).get("matchLabels", {})
        if (labels.get("app.kubernetes.io/instance") == HUB_RELEASE
                and selector and all(pod.get("metadata", {}).get("labels", {}).get(key) == value
                                     for key, value in selector.items()
                                     for pod in pods_before.values())):
            chart_candidates.append(candidate)
    chart_policy = chart_candidates[0] if len(chart_candidates) == 1 else {}
    chart_spec = chart_policy.get("spec", {})
    selectors_match = len(chart_candidates) == 1
    no_chart_ipblocks = not any("ipBlock" in peer
                                for rule in chart_spec.get("egress", [])
                                for peer in rule.get("to", []))
    chart_policy_ok = (len(chart_candidates) == 1
                       and chart_policy.get("metadata", {}).get("namespace") == NAMESPACE
                       and "Egress" in chart_spec.get("policyTypes", [])
                       and selectors_match and no_chart_ipblocks)
    custom_policy_ok = all(_policy_exact(lab, "saf-hub-egress-" + owner,
                                         user, owner)
                           for user, owner in users.items())

    expected = {HUB_ALICE + "_to_own": "ALLOW:benign-dataset-alice",
                HUB_BOB + "_to_own": "ALLOW:benign-dataset-bob",
                HUB_ALICE + "_to_" + HUB_BOB: "BLOCKED",
                HUB_BOB + "_to_" + HUB_ALICE: "BLOCKED"}
    deadline = time.monotonic() + 35
    consecutive = 0
    after = {}
    while time.monotonic() < deadline:
        after = observe_paths()
        consecutive = consecutive + 1 if after == expected else 0
        if consecutive == 2:
            break
    route_ready = _run_post_policy_route_probe(lab)
    pods_after = _owned_hub_user_pods(lab)
    stable_pods = all(pods_before[user]["metadata"]["uid"] == pods_after[user]["metadata"]["uid"]
                      for user in users)
    endpoints_after = {user: _dataset_identity(lab, "dataset-" + owner, owner)
                       for user, owner in users.items()}
    stable_endpoints = all(endpoints_before[user]["uid"] == endpoints_after[user]["uid"]
                           and endpoints_before[user]["pod_ip"] == endpoints_after[user]["pod_ip"]
                           for user in users)
    passed = (chart_policy_ok and custom_policy_ok and consecutive == 2
              and stable_pods and stable_endpoints and route_ready)
    (lab.evidence / "hub-spawned-egress.raw.json").write_text(json.dumps({
        "scope": "case-owned synthetic users, exact KubeSpawner Pod UIDs, and two inert local endpoint Pods",
        "hub_user_pods_before": {user: {"name": pod["metadata"]["name"],
                                        "uid": pod["metadata"]["uid"],
                                        "labels": pod["metadata"].get("labels", {}),
                                        "ready": _pod_ready(pod)} for user, pod in pods_before.items()},
        "hub_user_pods_after": {user: {"name": pod["metadata"]["name"],
                                       "uid": pod["metadata"]["uid"],
                                       "ready": _pod_ready(pod)} for user, pod in pods_after.items()},
        "endpoints_before": endpoints_before, "endpoints_after": endpoints_after,
        "baseline_matrix": baseline, "post_policy_matrix": after,
        "post_policy_stable_matches": consecutive,
        "chart_singleuser_policy": {"name": chart_policy.get("metadata", {}).get("name"),
                                    "pod_selector": chart_spec.get("podSelector"),
                                    "policy_types": chart_spec.get("policyTypes"),
                                    "egress_peer_kinds": [list(peer.keys()) for rule in chart_spec.get("egress", [])
                                                          for peer in rule.get("to", [])],
                                    "selects_both_user_pods": selectors_match,
                                    "has_no_ip_block_peers": no_chart_ipblocks},
        "user_policy_readback": {"alice_exact": _policy_exact(lab, "saf-hub-egress-alice", HUB_ALICE, "alice"),
                                 "bob_exact": _policy_exact(lab, "saf-hub-egress-bob", HUB_BOB, "bob")},
        "post_policy_authenticated_hub_routes_ready": route_ready,
    }, indent=2, sort_keys=True) + "\n")
    lab.check("green", "Per-user egress policies on the actual Hub-spawned notebook Pods preserve each owned dataset route and block the other user's endpoint",
              passed,
              {"case_chart_egress_policy_selects_both_spawned_pods": chart_policy_ok,
               "alice_egress_policy_exact": _policy_exact(lab, "saf-hub-egress-alice", HUB_ALICE, "alice"),
               "bob_egress_policy_exact": _policy_exact(lab, "saf-hub-egress-bob", HUB_BOB, "bob"),
               "baseline_cross_user_paths_reachable": baseline[HUB_ALICE + "_to_" + HUB_BOB].startswith("ALLOW:")
                   and baseline[HUB_BOB + "_to_" + HUB_ALICE].startswith("ALLOW:"),
               "own_routes_allowed_cross_routes_blocked_twice": consecutive == 2,
               "same_user_and_endpoint_uids_observed": stable_pods and stable_endpoints,
               "authenticated_hub_routes_remain_ready": route_ready})


def _hub_user_pods(lab, user=HUB_USER):
    query = ("{range .items[*]}{.metadata.uid}{\"|\"}{.spec.serviceAccountName}{\"|\"}"
             "{.spec.containers[0].image}{\"|\"}{.status.phase}{\"\\n\"}{end}")
    result = lab.kubectl("get", "pods", "-l", f"hub.jupyter.org/username={user}", "-o", f"jsonpath={query}")
    return [line.split("|") for line in result.stdout.splitlines() if line]


def _hub_terminal_config_mount(lab, user):
    selected = json.loads(lab.kubectl(
        "get", "pods", "-l", f"hub.jupyter.org/username={user}", "-o", "json").stdout).get("items", [])
    if len(selected) != 1 or not _pod_ready(selected[0]):
        return False
    pod = selected[0]
    spec = pod.get("spec", {})
    if not any(container.get("image") == SINGLEUSER_IMAGE for container in spec.get("containers", [])):
        return False
    volumes = spec.get("volumes", [])
    expected_key = "saf-terminals-disabled.py"
    matching = [volume for volume in volumes
                if volume.get("secret", {}).get("secretName") == "singleuser"
                and any(item.get("key") == expected_key and item.get("path") == expected_key
                        for item in volume.get("secret", {}).get("items", []))]
    if len(matching) != 1:
        return False
    volume_name = matching[0].get("name")
    containers = spec.get("containers", [])
    main = [container for container in containers
            if any(mount.get("name") == volume_name
                   and mount.get("mountPath") == "/etc/jupyter/jupyter_server_config.py"
                   and mount.get("subPath") == expected_key
                   for mount in container.get("volumeMounts", []))]
    if len(main) != 1:
        return False
    name = pod.get("metadata", {}).get("name")
    # Fixed read-only inspection of the exact mounted file; output is limited to
    # existence, a digest, and the one reviewed trait assignment.
    inspector = ("import hashlib,json,pathlib,jupyter_server; p=pathlib.Path('/etc/jupyter/jupyter_server_config.py'); "
                 "b=p.read_bytes(); print(json.dumps({'exists':True,'sha256':hashlib.sha256(b).hexdigest(),"
                 "'disabled_line':b'c.ServerApp.terminals_enabled = False' in b,"
                 "'jupyter_server_version':jupyter_server.__version__}))")
    observed = lab.kubectl("exec", name, "-c", main[0]["name"], "--", "python", "-B", "-c", inspector,
                           timeout=12).stdout.strip()
    try:
        result = json.loads(observed)
    except json.JSONDecodeError:
        return False
    expected_hash = hashlib.sha256(HUB_EXTENSION_CONFIG.encode()).hexdigest()
    return {"mounted_config_ok": result.get("exists") is True
            and result.get("sha256") == expected_hash
            and result.get("disabled_line") is True,
            "jupyter_server_version": result.get("jupyter_server_version", "")}


def _hub_extension_identity(lab, user):
    selected = json.loads(lab.kubectl(
        "get", "pods", "-l", f"hub.jupyter.org/username={user}", "-o", "json").stdout).get("items", [])
    if len(selected) != 1 or not _pod_ready(selected[0]):
        return {}
    pod = selected[0]
    spec = pod.get("spec", {})
    if (pod.get("metadata", {}).get("namespace") != NAMESPACE
            or not pod.get("metadata", {}).get("uid")
            or not any(container.get("image") == SINGLEUSER_IMAGE
                       for container in spec.get("containers", []))):
        return {}
    expected = {
        "saf-terminals-disabled.py": "/etc/jupyter/jupyter_server_config.py",
        "saf-approved-extension.py": "/opt/saf-jupyter-extensions/saf_approved_extension.py",
        "saf-unapproved-extension.py": "/opt/saf-jupyter-extensions/saf_unapproved_extension.py",
    }
    secret_volumes = [volume for volume in spec.get("volumes", [])
                      if volume.get("secret", {}).get("secretName") == "singleuser"]
    if len(secret_volumes) != 1:
        return {}
    volume = secret_volumes[0]
    keys = {item.get("key") for item in volume.get("secret", {}).get("items", [])}
    if not set(expected).issubset(keys):
        return {}
    main = [container for container in spec.get("containers", [])
            if all(any(mount.get("name") == volume.get("name")
                       and mount.get("mountPath") == path
                       and mount.get("subPath") == key
                       for mount in container.get("volumeMounts", []))
                   for key, path in expected.items())]
    if len(main) != 1:
        return {}
    name = pod["metadata"]["name"]
    inspector = r'''import hashlib,json,pathlib,jupyter_server
paths={"config":"/etc/jupyter/jupyter_server_config.py",
       "approved":"/opt/saf-jupyter-extensions/saf_approved_extension.py",
       "unapproved":"/opt/saf-jupyter-extensions/saf_unapproved_extension.py"}
data={name:pathlib.Path(path).read_bytes() for name,path in paths.items()}
versions={}
for name,path in (("approved","/opt/saf-jupyter-extensions/saf_approved_extension.py"),
                  ("unapproved","/opt/saf-jupyter-extensions/saf_unapproved_extension.py")):
    text=pathlib.Path(path).read_text()
    versions[name]="1.0.0" if 'FIXTURE_VERSION = "1.0.0"' in text else ""
print(json.dumps({"jupyter_server_version":jupyter_server.__version__,
 "hashes":{name:hashlib.sha256(value).hexdigest() for name,value in data.items()},
 "versions":versions},sort_keys=True))'''
    try:
        observed = json.loads(lab.kubectl("exec", name, "-c", main[0]["name"], "--",
            "python", "-B", "-c", inspector, timeout=12).stdout.strip())
    except (json.JSONDecodeError, KeyError):
        return {}
    expected_hashes = {
        "config": hashlib.sha256(HUB_EXTENSION_CONFIG.encode()).hexdigest(),
        "approved": hashlib.sha256(APPROVED_EXTENSION_SOURCE.encode()).hexdigest(),
        "unapproved": hashlib.sha256(UNAPPROVED_EXTENSION_SOURCE.encode()).hexdigest(),
    }
    identity_before = {"uid": pod["metadata"]["uid"], "ready": _pod_ready(pod)}
    refreshed = json.loads(lab.kubectl("get", "pods", name, "-o", "json").stdout)
    identity_after = {"uid": refreshed.get("metadata", {}).get("uid"), "ready": _pod_ready(refreshed)}
    return {"uid_before": identity_before["uid"], "uid_after": identity_after["uid"],
            "ready_before": identity_before["ready"], "ready_after": identity_after["ready"],
            "mounted_files_match": observed.get("hashes") == expected_hashes,
            "sha256": observed.get("hashes", {}),
            "jupyter_server_version": observed.get("jupyter_server_version"),
            "approved_version": observed.get("versions", {}).get("approved"),
            "unapproved_version": observed.get("versions", {}).get("unapproved"),
            "hashes_match": observed.get("hashes") == expected_hashes}


def _save_failure_diagnostics(lab, password):
    try:
        outcome = subprocess.run(
            ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
             "--namespace", NAMESPACE, "--request-timeout=12s", "logs", "deployment/hub", "--tail=100"],
            env=lab.env, capture_output=True, text=True, timeout=16, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return
    frames = []
    errors = []
    for line in outcome.stdout.splitlines():
        frame = re.search(r'File "([^"]+\.py)", line ([0-9]+), in ([A-Za-z0-9_<>]+)', line)
        if frame:
            frames.append({"file": Path(frame[1]).name, "line": int(frame[2]), "method": frame[3]})
        failure = re.fullmatch(r"\s*([A-Za-z_.]+(?:Error|Exception)): (.{1,220})", line)
        if failure:
            details = failure[2]
            if password in details or re.search(r"password|token|secret|credential|authorization", details, re.I):
                details = "[protected diagnostic]"
            else:
                details = re.sub(r"[A-Za-z0-9_-]{25,}", "[redacted]", details)
            errors.append({"type": failure[1], "details": details})
    (lab.evidence / "hub-failure-diagnostics.json").write_text(
        json.dumps({"frames": frames[-12:], "errors": errors[-5:]}, indent=2) + "\n")


def _exercise_hub_identity(lab):
    password = secrets.token_urlsafe(32)
    values = _hub_values()
    try:
        with tempfile.TemporaryDirectory(prefix="saf-hub-values-") as directory:
            os.chmod(directory, 0o700)
            values_path = Path(directory) / "values.json"
            values_path.write_text(json.dumps(values))
            values_path.chmod(0o600)
            _render_chart(lab, values_path)

            lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                        "metadata": {"name": HUB_USER_SA, "namespace": NAMESPACE,
                                     "labels": {"saf.example/fixture": "hub-auth"}},
                        "automountServiceAccountToken": False})
            _create_password_secret(lab, password)
            lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                        "metadata": {"name": "saf-hub-probe", "namespace": NAMESPACE,
                                     "labels": {"saf.example/fixture": "hub-auth"}},
                        "data": {HUB_PROBE_SCRIPT: _hub_probe_source(),
                                 HUB_WORKSPACE_SCRIPT: _hub_workspace_matrix_source(),
                                 HUB_ROUTE_SCRIPT: _hub_route_probe_source()}})
            lab.command(*_helm_args(lab), "upgrade", "--install", HUB_RELEASE, str(CHART), "--namespace", NAMESPACE,
                        "--values", str(values_path), "--wait", "--timeout", "240s", timeout=250)
            lab.kubectl("rollout", "status", "deployment/hub", "--timeout=180s", timeout=190)
            lab.kubectl("rollout", "status", "deployment/proxy", "--timeout=180s", timeout=190)

        # The denied arm and API-side absence check precede the only successful login.
        denied = _run_job(lab, "saf-hub-auth-denied", "deny")
        no_pods_before_allow = not _hub_user_pods(lab)
        if denied.get("login_refused") is not True or denied.get("session_cookie_absent") is not True or not no_pods_before_allow:
            lab.block("The fixed wrong-password control did not remain unauthenticated and unspawned")

        allowed = _run_job(lab, "saf-hub-auth-allowed", "allow")
        rows = _hub_user_pods(lab)
        if len(rows) != 1 or len(rows[0]) != 4:
            lab.block("The successful login did not produce exactly one queryable Hub user Pod")
        uid, service_account, image, phase = rows[0]
        lab.kubectl("wait", "--for=condition=Ready", "pod",
                     "-l", f"hub.jupyter.org/username={HUB_USER}", "--timeout=30s", timeout=40)
        rows = _hub_user_pods(lab)
        if len(rows) != 1 or len(rows[0]) != 4:
            lab.block("The Hub user Pod identity changed while waiting for readiness")
        uid, service_account, image, phase = rows[0]
        matched = (
            allowed.get("authenticated_cookie_seen") is True
            and allowed.get("spawned_server_route_ok") is True
            and bool(uid) and service_account == HUB_USER_SA
            and image == SINGLEUSER_IMAGE and phase == "Running"
        )
        lab.check(
            "positive",
            "One allowlisted synthetic Hub login rejects a wrong password and routes an authenticated session to its KubeSpawner Pod",
            matched,
            {"wrong_password_denied": True, "wrong_password_created_no_pod": no_pods_before_allow,
             "successful_login_session": allowed.get("authenticated_cookie_seen") is True,
             "spawned_server_route_ok": allowed.get("spawned_server_route_ok") is True,
             "exactly_one_user_pod": len(rows) == 1, "pod_uid_present": bool(uid),
             "hub_username_selector_matched": len(rows) == 1,
             "dedicated_tokenless_service_account": service_account == HUB_USER_SA,
             "approved_singleuser_image": image == SINGLEUSER_IMAGE, "pod_running_and_ready": phase == "Running"},
        )
        (lab.evidence / "hub-auth-summary.json").write_text(json.dumps(lab.checks[-1], indent=2) + "\n")
        _exercise_hub_workspace_matrix(lab)
    except Exception:
        _save_failure_diagnostics(lab, password)
        raise
    finally:
        # Remove only this fixture's spawned identity and named resources; the
        # runner also deletes its uniquely named cluster on every terminal path.
        try:
            for user in (HUB_USER, HUB_ALICE, HUB_BOB):
                lab.kubectl("delete", "pods", "-l", f"hub.jupyter.org/username={user}",
                            "--ignore-not-found=true", allow_failure=True)
            lab.command(*_helm_args(lab), "uninstall", HUB_RELEASE, "--namespace", NAMESPACE,
                        allow_failure=True, timeout=45)
            for kind, name in (("job", "saf-hub-auth-denied"), ("job", "saf-hub-auth-allowed"),
                               ("job", "saf-hub-workspace-matrix"),
                               ("job", "saf-hub-egress-route-probe"),
                               ("networkpolicy", "saf-hub-egress-alice"),
                               ("networkpolicy", "saf-hub-egress-bob"),
                               ("configmap", "saf-hub-probe"), ("serviceaccount", HUB_USER_SA),
                               ("secret", HUB_SECRET)):
                lab.kubectl("delete", kind, name, "--ignore-not-found=true", allow_failure=True)
        except Exception:
            # Whole-cluster cleanup in the runner remains the final owner.
            pass
