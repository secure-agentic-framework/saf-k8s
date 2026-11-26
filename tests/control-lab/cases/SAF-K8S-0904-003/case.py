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
    "after policy is active. Kernel exposure, optional extensions, JupyterHub authentication, "
    "full provenance and dataset policy, and deployed controls require separate evidence."
)

ROOT = Path(__file__).resolve().parent

HUB_RELEASE = "saf-jhub"
HUB_USER = "saf-fixture-user"
HUB_USER_SA = "saf-hub-user"
HUB_SECRET = "saf-hub-password"
HUB_PROBE_SCRIPT = "hub-auth-probe.py"
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


def probe(lab, source, destination):
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
    result = lab.kubectl("exec", source, "--", "/opt/conda/bin/python", "-B",
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
                "Authenticator": {"allow_all": False, "allowed_users": [HUB_USER], "admin_users": []},
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
            "networkPolicy": {"enabled": False},
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


def _hub_user_pods(lab):
    query = ("{range .items[*]}{.metadata.uid}{\"|\"}{.spec.serviceAccountName}{\"|\"}"
             "{.spec.containers[0].image}{\"|\"}{.status.phase}{\"\\n\"}{end}")
    result = lab.kubectl("get", "pods", "-l", f"hub.jupyter.org/username={HUB_USER}", "-o", f"jsonpath={query}")
    return [line.split("|") for line in result.stdout.splitlines() if line]


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
                        "data": {HUB_PROBE_SCRIPT: _hub_probe_source()}})
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
    except Exception:
        _save_failure_diagnostics(lab, password)
        raise
    finally:
        # Remove only this fixture's spawned identity and named resources; the
        # runner also deletes its uniquely named cluster on every terminal path.
        try:
            lab.kubectl("delete", "pods", "-l", f"hub.jupyter.org/username={HUB_USER}",
                        "--ignore-not-found=true", allow_failure=True)
            lab.command(*_helm_args(lab), "uninstall", HUB_RELEASE, "--namespace", NAMESPACE,
                        allow_failure=True, timeout=45)
            for kind, name in (("job", "saf-hub-auth-denied"), ("job", "saf-hub-auth-allowed"),
                               ("configmap", "saf-hub-probe"), ("serviceaccount", HUB_USER_SA),
                               ("secret", HUB_SECRET)):
                lab.kubectl("delete", kind, name, "--ignore-not-found=true", allow_failure=True)
        except Exception:
            # Whole-cluster cleanup in the runner remains the final owner.
            pass
