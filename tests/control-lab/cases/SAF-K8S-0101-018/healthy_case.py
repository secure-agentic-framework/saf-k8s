"""Verify a healthy kubeadm API server after disabling anonymous authentication."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time

USER = "saf-health-probe"
CSR = "saf-health-probe"
MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"
NODE_CONFIG = "/var/lib/saf-health-probe/kubeconfig"
PROBE_CONFIG = "/saf-health-probe/kubeconfig"
PROBE_BIN = "/saf-health-probe/kubectl"
SCOPE = (
    "Pinned single-node kind/kubeadm. Check anonymous HTTP rejection, real kubelet "
    "probe failure with an anonymous probe, then sustained Ready with a temporary "
    "RBAC-scoped authenticated probe. Managed control-plane coverage is separate."
)

baseline_spec = importlib.util.spec_from_file_location(
    "anonymous_baseline", Path(__file__).with_name("case.py"))
baseline = importlib.util.module_from_spec(baseline_spec)
baseline_spec.loader.exec_module(baseline)


def private_command(lab, *command, payload=None, allow_failure=False):
    try:
        result = subprocess.run(command, input=payload, capture_output=True, text=True,
                                env=lab.env, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as error:
        if allow_failure:
            return None
        lab.block(f"Private command {command[0]} failed: {type(error).__name__}")
    if result.returncode and not allow_failure:
        lab.block(f"Private command {command[0]} returned {result.returncode}")
    return result


def install_probe_identity(lab, node, directory, prefix):
    role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
            "metadata": {"name": USER},
            "rules": [{"nonResourceURLs": ["/livez", "/readyz"], "verbs": ["get"]}]}
    binding = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
               "metadata": {"name": USER},
               "subjects": [{"kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": USER}],
               "roleRef": {"kind": "ClusterRole", "apiGroup": "rbac.authorization.k8s.io", "name": USER}}
    for resource in (role, binding):
        lab.kubectl("create", "-f", "-", "-o", "name", payload=json.dumps(resource))

    key = directory / "probe.key"
    csr = directory / "probe.csr"
    private_command(lab, "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={USER}")
    key.chmod(0o600)
    request = {"apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest",
               "metadata": {"name": CSR}, "spec": {
                   "request": base64.b64encode(csr.read_bytes()).decode(),
                   "signerName": "kubernetes.io/kube-apiserver-client", "expirationSeconds": 3600,
                   "usages": ["digital signature", "key encipherment", "client auth"]}}
    private_command(lab, *prefix, "create", "-f", "-", payload=json.dumps(request))
    lab.kubectl("certificate", "approve", CSR)

    certificate = ""
    deadline = time.monotonic() + 45
    while not certificate and time.monotonic() < deadline:
        certificate = private_command(lab, *prefix, "get", "csr", CSR,
                                      "-o", "jsonpath={.status.certificate}").stdout.strip()
        if not certificate:
            time.sleep(0.5)
    if not certificate:
        lab.block("The restricted health CSR did not receive a certificate")

    address, port, ca = baseline.loopback_endpoint_and_ca(lab, lab.kubeconfig, lab.cluster)
    server = f"https://[{address}]:{port}" if ":" in address else f"https://{address}:{port}"
    config = {
        "apiVersion": "v1", "kind": "Config", "current-context": "fixture",
        "clusters": [{"name": "fixture", "cluster": {
            "server": server, "certificate-authority-data": base64.b64encode(ca.encode()).decode()}}],
        "users": [{"name": USER, "user": {"client-certificate-data": certificate,
                                         "client-key-data": base64.b64encode(key.read_bytes()).decode()}}],
        "contexts": [{"name": "fixture", "context": {"cluster": "fixture", "user": USER}}],
    }
    host_config = directory / "probe.kubeconfig"
    host_config.touch(mode=0o600)
    host_config.write_text(json.dumps(config))
    config["clusters"][0]["cluster"].update(server="https://127.0.0.1:6443",
                                          **{"tls-server-name": "kubernetes"})
    private_command(lab, "docker", "exec", "-i", node, "sh", "-ceu",
                    'umask 077; mkdir -p /var/lib/saf-health-probe; cat > "$1"; test -x /usr/bin/kubectl',
                    "probe-config", NODE_CONFIG, payload=json.dumps(config))
    return host_config


def verify_scoped_access(lab, credentials):
    prefix = ("kubectl", "--kubeconfig", str(credentials), "--request-timeout=10s", "get")
    health = [private_command(lab, *prefix, f"--raw={path}").stdout.strip()
              for path in ("/livez", "/readyz")]
    denied = private_command(lab, *prefix, "--raw=/api/v1/namespaces", allow_failure=True)
    forbidden = bool(denied and denied.returncode and "forbidden" in denied.stderr.lower())
    lab.check("positive", "Scoped identity can read health and receives Forbidden for namespace data",
              health == ["ok", "ok"] and forbidden, {"health": health, "namespace_forbidden": forbidden})


def apiserver_container(manifest):
    return next(item for item in manifest["spec"]["containers"] if item["name"] == "kube-apiserver")


def write_manifest(lab, node, manifest):
    command = ('umask 077; tmp=$(mktemp /etc/kubernetes/.saf-probe.XXXXXX); '
               'trap \'rm -f "$tmp"\' EXIT; cat > "$tmp"; mv -f "$tmp" "$1"')
    private_command(lab, "docker", "exec", "-i", node, "sh", "-ceu",
                    command, "manifest-update", MANIFEST, payload=json.dumps(manifest))


def status(lab, prefix, name):
    result = private_command(lab, *prefix, "-n", "kube-system", "get", "pod", name, "-o",
                             "json", allow_failure=True)
    if not result or result.returncode:
        return None
    return json.loads(result.stdout)["status"]


def ready(state):
    return any(row.get("type") == "Ready" and row.get("status") == "True"
               for row in (state or {}).get("conditions", []))


def kubelet_probe_rejections(lab, prefix, name):
    response = private_command(
        lab, *prefix, "-n", "kube-system", "get", "events", "--field-selector",
        f"involvedObject.name={name},reason=Unhealthy", "-o", "json", allow_failure=True)
    if not response or response.returncode:
        return []
    return sorted({row.get("message", "") for row in json.loads(response.stdout)["items"]
                   if "probe failed" in row.get("message", "").lower() and "401" in row["message"]})


def verify_unauthenticated_startup_failure(lab, prefix, node, name):
    """Attribute the measured probe failure to the current static-Pod configuration."""
    outcome = {"current_http_startup_probe": False, "unready": False,
               "startup_probe_failed": False, "matching_https_status": None}
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        response = private_command(lab, *prefix, "-n", "kube-system", "get", "pod", name,
                                   "-o", "json", allow_failure=True)
        if not response or response.returncode:
            time.sleep(2)
            continue
        pod = json.loads(response.stdout)
        container = apiserver_container(pod)
        outcome["current_http_startup_probe"] = (
            "--anonymous-auth=false" in container["command"]
            and container["startupProbe"].get("httpGet", {}).get("path") == "/livez"
        )
        outcome["unready"] = not ready(pod["status"])
        if not outcome["current_http_startup_probe"] or not outcome["unready"]:
            time.sleep(2)
            continue
        uid = pod["metadata"].get("annotations", {}).get("kubernetes.io/config.mirror")
        metrics = private_command(lab, *prefix, "get",
                                  f"--raw=/api/v1/nodes/{node}/proxy/metrics/probes", allow_failure=True)
        if uid and metrics and metrics.returncode == 0:
            expected = {
                "container": "kube-apiserver", "namespace": "kube-system", "pod": name,
                "pod_uid": uid, "probe_type": "Startup", "result": "failed",
            }
            for line in metrics.stdout.splitlines():
                if line.startswith("prober_probe_total{"):
                    labels, _, number = line.partition("}")
                    observed = dict(re.findall(r'(\w+)="([^"]*)"', labels))
                    if observed == expected and float(number.strip()) > 0:
                        outcome["startup_probe_failed"] = True
                        break
        replied = baseline.anonymous_get(
            lab, lab.kubeconfig, lab.cluster, "/livez", allow_unavailable=True,
        )
        outcome["matching_https_status"] = replied["status"] if replied else None
        if outcome["startup_probe_failed"] and outcome["matching_https_status"] == 401:
            break
        time.sleep(2)
    lab.check("red", "The current unauthenticated startup probe fails while the same HTTPS path returns 401",
              all(outcome[key] for key in ("current_http_startup_probe", "unready", "startup_probe_failed"))
              and outcome["matching_https_status"] == 401, outcome)


def verify_health_only(lab, node, name, prefix, manifest):
    config_path = "/etc/kubernetes/pki/saf-anonymous-health.json"
    allowed_paths = ("/livez", "/readyz", "/healthz")
    config = {"apiVersion": "apiserver.config.k8s.io/v1", "kind": "AuthenticationConfiguration",
              "anonymous": {"enabled": True,
                            "conditions": [{"path": path} for path in allowed_paths]}}
    lab.command("docker", "exec", "-i", node, "sh", "-ceu", 'umask 022; cat >"$1"',
                "saf-auth-config", config_path, payload=json.dumps(config))
    profile = copy.deepcopy(manifest)
    command = apiserver_container(profile)["command"]
    if any(arg.startswith("--authentication-config") for arg in command):
        lab.block("The test profile already has an authentication configuration")
    command.remove("--anonymous-auth=false")
    command.append("--authentication-config=" + config_path)

    rejected = baseline.anonymous_get(lab, lab.kubeconfig, lab.cluster, "/version")
    lab.check("positive", "Full disablement returns HTTP 401 for the ordinary version path",
              rejected["status"] == 401, rejected)
    write_manifest(lab, node, profile)
    observed = None
    non_health = None
    deadline = time.monotonic() + 110
    while time.monotonic() < deadline:
        observed = baseline.anonymous_get(
            lab, lab.kubeconfig, lab.cluster, "/livez", allow_unavailable=True,
        )
        if observed and observed["status"] == 200 and ready(status(lab, prefix, name)):
            non_health = baseline.anonymous_get(
                lab, lab.kubeconfig, lab.cluster, "/version", allow_unavailable=True,
            )
            if non_health:
                break
        time.sleep(2)
    if not non_health:
        lab.block("The configured health-only profile did not become ready")
    lab.check("green", "The scoped profile allows anonymous liveness and explicitly rejects anonymous version requests",
              observed["status"] == 200 and non_health["status"] == 401,
              {"health": observed, "non_health": non_health, "allowed_health_paths": allowed_paths})
    health, namespace = baseline.authorized_health_and_api(lab, lab.cluster)
    lab.check("positive", "Authorized health and the ordinary namespace read work in the health-only profile",
              health == "ok" and namespace == "namespace/saf-test",
              {"authenticated_health": health == "ok", "authenticated_namespace": namespace})


def run(lab, *, compare_health_only=False):
    node = f"{lab.cluster}-control-plane"
    name = f"kube-apiserver-{node}"
    prefix = ("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
              f"kind-{lab.cluster}", "--request-timeout=10s")
    lab.kubectl("-n", "kube-system", "wait", f"pod/{name}", "--for=condition=Ready", "--timeout=60s",
                timeout=75)
    original = baseline.anonymous_get_livez(lab, lab.kubeconfig, lab.cluster)
    lab.check("red", "Default API server answers an unauthenticated health request",
              original["status"] == 200, original)

    with tempfile.TemporaryDirectory(prefix="saf-authenticated-health-") as temp:
        credentials = install_probe_identity(lab, node, Path(temp), prefix)
        verify_scoped_access(lab, credentials)
        raw = private_command(lab, "docker", "exec", node, "cat", MANIFEST).stdout
        parsed = private_command(lab, *prefix, "create", "--dry-run=client", "--validate=false",
                                 "-f", "-", "-o", "json", payload=raw)
        red = json.loads(parsed.stdout)
        container = apiserver_container(red)
        probe_paths = {"startupProbe": "/livez", "livenessProbe": "/livez", "readinessProbe": "/readyz"}
        for name_key, path in probe_paths.items():
            http = container[name_key].get("httpGet", {})
            if http.get("path") != path or http.get("scheme") != "HTTPS":
                lab.block(f"Unexpected kubeadm HTTP probe configuration for {name_key}")
        container["command"] = [part for part in container["command"]
                                if not part.startswith("--anonymous-auth=")] + ["--anonymous-auth=false"]

        green = copy.deepcopy(red)
        control = apiserver_container(green)
        for name_key, path in probe_paths.items():
            probe = control[name_key]
            del probe["httpGet"]
            probe["exec"] = {"command": [PROBE_BIN, f"--kubeconfig={PROBE_CONFIG}",
                                         "--request-timeout=5s", "get", f"--raw={path}"]}
        for mount, host_path in ((PROBE_CONFIG, NODE_CONFIG), (PROBE_BIN, "/usr/bin/kubectl")):
            volume = "saf-probe-" + Path(mount).name
            control["volumeMounts"].append({"name": volume, "mountPath": mount, "readOnly": True})
            green["spec"]["volumes"].append({"name": volume, "hostPath": {"path": host_path, "type": "File"}})

        write_manifest(lab, node, red)
        if compare_health_only:
            verify_unauthenticated_startup_failure(lab, prefix, node, name)
        else:
            warnings = []
            deadline = time.monotonic() + 80
            while time.monotonic() < deadline:
                warnings = kubelet_probe_rejections(lab, prefix, name)
                state = status(lab, prefix, name)
                if warnings and state and not ready(state):
                    break
                time.sleep(2)
            lab.check("red", "Kubelet's unauthenticated probes receive 401 and the static Pod is unready",
                      bool(warnings and state and not ready(state)),
                      {"ready": ready(state), "warnings": warnings})

        write_manifest(lab, node, green)
        deadline = time.monotonic() + 145
        while not ready(status(lab, prefix, name)):
            if time.monotonic() >= deadline:
                lab.block("The API server did not become Ready with the authenticated probes")
            time.sleep(2)
        after = baseline.anonymous_get_livez(lab, lab.kubeconfig, lab.cluster)
        lab.check("green", "Authenticated kubelet probes restore Ready while anonymous health returns 401",
                  after["status"] == 401 and ready(status(lab, prefix, name)), after)

        observed = []
        period = max(control[key].get("periodSeconds", 10) for key in probe_paths)
        for sample in range(3):
            if sample:
                time.sleep(period)
            current = status(lab, prefix, name)
            counts = (current or {}).get("containerStatuses", [])
            observed.append((ready(current), tuple((x["containerID"], x["restartCount"]) for x in counts)))
        lab.check("positive", "The API server stays Ready with the same container across all probe intervals",
                  all(item[0] and item[1] for item in observed)
                  and all(item[1] == observed[0][1] for item in observed),
                  {"ready": [item[0] for item in observed], "interval_seconds": period})
        verify_scoped_access(lab, credentials)
        namespace = lab.kubectl("get", "namespace", "saf-test", "-o", "name").stdout.strip()
        lab.check("positive", "Authenticated ordinary API access still works",
                  namespace == "namespace/saf-test", namespace)

        if compare_health_only:
            verify_health_only(lab, node, name, prefix, green)
