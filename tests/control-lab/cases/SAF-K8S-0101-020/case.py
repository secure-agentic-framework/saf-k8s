"""Compare the kube-apiserver pprof index with profiling enabled and disabled."""
from contextlib import contextmanager
import base64
import http.client
import ipaddress
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
from time import monotonic, sleep
import urllib.parse


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
NAMESPACE = "saf-test"
TIMEOUT = 8
PPROF_INDEX = "/debug/pprof/"
HEALTH_PATH = "/livez"
ALLOWED_PATHS = frozenset((PPROF_INDEX, HEALTH_PATH))
FIXTURE_READER = "saf-lab-diagnostic-reader"
READER_ROLE = "saf-lab-pprof-index-reader"
DIAGNOSTIC_PERMISSIONS = (
    ("get", "/debug/flags"),
    ("put", "/debug/flags/v"),
    ("get", "/metrics"),
    ("delete", "/metrics"),
    ("delete", "/metrics/slis"),
)
SCOPE = (
    "Only authenticated HTTPS GET requests to /debug/pprof/ and /livez on two "
    "case-owned Kubernetes v1.36.1 kind API-server localhost endpoints, comparing "
    "explicit --profiling=true with --profiling=false. Index response bodies are "
    "discarded. The exact effective profiling argument and configured "
    "--debug-socket-path value are inspected in each static API-server Pod command; "
    "no socket is opened or queried. The RBAC comparison checks an impersonated fixture reader "
    "before and after an exact index-only grant. Authorization reviews for other diagnostic "
    "permissions do not invoke those handlers. Managed and production configurations are outside scope."
)


def config_json(lab, kubeconfig, cluster):
    """Load the selected runner-owned kubeconfig in memory, without logging secrets."""
    expected = f"kind-{cluster}"
    result = subprocess.run(
        ["kubectl", "config", "view", "--kubeconfig", str(kubeconfig),
         "--context", expected, "--minify", "--raw", "-o", "json"],
        env=lab.env, capture_output=True, text=True, timeout=TIMEOUT, check=False,
    )
    if result.returncode:
        lab.block(f"Could not read selected kubeconfig for {expected}")
    try:
        config = json.loads(result.stdout)
        context = config["contexts"][0]
        cluster_row = config["clusters"][0]
        user_row = config["users"][0]
    except (ValueError, KeyError, IndexError, TypeError):
        lab.block(f"Malformed selected kubeconfig for {expected}")
    if context.get("name") != expected:
        lab.block(f"Expected kubeconfig context {expected}")
    if context.get("context", {}).get("cluster") != cluster_row.get("name"):
        lab.block(f"Selected cluster does not match context {expected}")
    if context.get("context", {}).get("user") != user_row.get("name"):
        lab.block(f"Selected user does not match context {expected}")
    return cluster_row.get("cluster", {}), user_row.get("user", {})


def material(value, field, directory):
    """Resolve a selected kubeconfig PEM field into a private temporary file."""
    if value is None:
        return None
    if field.endswith("-data"):
        try:
            data = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid kubeconfig {field}")
    else:
        data = Path(value).read_bytes()
    path = Path(directory) / field.replace("-", "_")
    path.write_bytes(data)
    os.chmod(path, 0o600)
    return path


def authenticated_status(lab, kubeconfig, cluster, path, *, fixture_reader=False):
    """GET one allowlisted local path with the lab identity or the fixed fixture reader."""
    if path not in ALLOWED_PATHS:
        lab.block(f"Refusing out-of-scope API path {path!r}")
    cluster_config, user_config = config_json(lab, kubeconfig, cluster)
    try:
        parsed = urllib.parse.urlsplit(cluster_config["server"])
        address = parsed.hostname
        port = parsed.port
        if parsed.scheme != "https" or not port or not ipaddress.ip_address(address).is_loopback:
            lab.block(f"Refusing non-HTTPS or non-loopback endpoint for kind-{cluster}")
        with tempfile.TemporaryDirectory(prefix="saf-pprof-client-") as temp:
            ca_file = material(cluster_config.get("certificate-authority-data") or
                               cluster_config.get("certificate-authority"),
                               "certificate-authority-data" if cluster_config.get(
                                   "certificate-authority-data") else "certificate-authority", temp)
            cert_file = material(user_config.get("client-certificate-data") or
                                 user_config.get("client-certificate"),
                                 "client-certificate-data" if user_config.get(
                                     "client-certificate-data") else "client-certificate", temp)
            key_file = material(user_config.get("client-key-data") or
                                user_config.get("client-key"),
                                "client-key-data" if user_config.get(
                                    "client-key-data") else "client-key", temp)
            if not ca_file or not cert_file or not key_file:
                lab.block(f"Selected kubeconfig lacks an approved TLS client identity for kind-{cluster}")
            context = ssl.create_default_context(cafile=str(ca_file))
            context.check_hostname = True
            context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
            connection = http.client.HTTPSConnection(
                address, port, timeout=TIMEOUT, context=context,
            )
            try:
                headers = {"Connection": "close"}
                if fixture_reader:
                    headers["Impersonate-User"] = FIXTURE_READER
                connection.request("GET", path, headers=headers)
                response = connection.getresponse()
                status = response.status
                response.read()  # Drain and discard; never return or log response content.
                return status
            finally:
                connection.close()
    except (OSError, ValueError, TypeError, KeyError, ssl.SSLError,
            http.client.HTTPException) as error:
        lab.block(f"Authenticated local GET {path} did not return an HTTP response: {type(error).__name__}")


def api_server_command(lab, kubeconfig, cluster):
    """Read only the effective kube-apiserver argument vector from its Pod spec."""
    result = subprocess.run(
        ["kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
         "-n", "kube-system", "get", f"pod/kube-apiserver-{cluster}-control-plane", "-o", "json"],
        env=lab.env, timeout=TIMEOUT + 5, capture_output=True, text=True,
    )
    if result.returncode:
        lab.block(f"Could not read the kube-apiserver mirror Pod for {cluster}")
    containers = json.loads(result.stdout)["spec"]["containers"]
    command = next(row["command"] for row in containers if row["name"] == "kube-apiserver")
    if not command or Path(command[0]).name != "kube-apiserver":
        lab.block(f"Unexpected kube-apiserver command for {cluster}")
    return command


def profiling_value(command):
    values = [arg.split("=", 1)[1] for arg in command
              if arg.startswith("--profiling=")]
    if any(arg == "--profiling" for arg in command) or len(values) != 1:
        return None
    return values[0]


def debug_socket_state(command):
    """Inspect only the configured path argument; never stat or connect to it."""
    values = []
    for index, arg in enumerate(command):
        if arg == "--debug-socket-path":
            values.append(command[index + 1] if index + 1 < len(command) else None)
        elif arg.startswith("--debug-socket-path="):
            values.append(arg.split("=", 1)[1])
    if not values:
        return "not-configured"
    if values == [""]:
        return "configured-empty"
    return "configured-nonempty"


def profile_config(profiling):
    return (
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "kubeadmConfigPatches:\n"
        "  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: ClusterConfiguration\n"
        "    apiServer:\n"
        "      extraArgs:\n"
        "        - name: profiling\n"
        f"          value: \"{profiling}\"\n"
    )


@contextmanager
def owned_profile(lab, label, profiling):
    cluster = f"{lab.cluster}-{label}"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block(f"Additional profiling profile already exists: {cluster}")
    with tempfile.TemporaryDirectory(prefix=f"saf-pprof-{label}-") as temp:
        kubeconfig = Path(temp) / "kubeconfig"
        config = Path(temp) / "kind.yaml"
        config.write_text(profile_config(profiling))
        attempted = False
        try:
            attempted = True
            lab.command("kind", "create", "cluster", "--name", cluster,
                        "--image", NODE_IMAGE, "--config", str(config),
                        "--kubeconfig", str(kubeconfig), "--wait", "90s", timeout=480)
            lab.command("kubectl", "--kubeconfig", str(kubeconfig), "--context",
                        f"kind-{cluster}", "create", "namespace", NAMESPACE, timeout=45)
            yield cluster, kubeconfig
        finally:
            if attempted:
                result = lab.command("kind", "delete", "cluster", "--name", cluster,
                                     "--kubeconfig", str(kubeconfig), timeout=90,
                                     allow_failure=True)
                if result.returncode:
                    lab.block(f"Could not confirm cleanup of profiling profile {cluster}")


def check_profile(lab, cluster, kubeconfig, expected, index_status):
    command = api_server_command(lab, kubeconfig, cluster)
    actual = profiling_value(command)
    sockets = debug_socket_state(command)
    lab.check(
        "red" if expected == "true" else "green",
        f"Effective kube-apiserver command has exactly --profiling={expected}",
        actual == expected,
        {"profiling": actual or "missing-or-ambiguous", "debug_socket": sockets},
    )
    lab.check(
        "green" if expected == "false" else "positive",
        "No nonempty --debug-socket-path is configured (independent of profiling)",
        sockets in ("not-configured", "configured-empty"),
        {"debug_socket": sockets},
    )
    status = authenticated_status(lab, kubeconfig, cluster, PPROF_INDEX)
    lab.check(
        "red" if expected == "true" else "green",
        f"Authenticated GET {PPROF_INDEX} returns HTTP {index_status} with profiling={expected}",
        status == index_status,
        {"method": "GET", "path": PPROF_INDEX, "status": status,
         "client": "selected kind kubeconfig mTLS", "response_body": "discarded"},
    )
    health = authenticated_status(lab, kubeconfig, cluster, HEALTH_PATH)
    lab.check(
        "positive",
        f"Authorized GET {HEALTH_PATH} remains HTTP 200 with profiling={expected}",
        health == 200,
        {"method": "GET", "path": HEALTH_PATH, "status": health,
         "client": "selected kind kubeconfig mTLS", "response_body": "discarded"},
    )


def api_request(lab, cluster, kubeconfig, resource):
    result = lab.command(
        "kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
        "create", "-f", "-", "-o", "json", payload=json.dumps(resource), timeout=30,
    )
    return json.loads(result.stdout)


def grant_index_reader(lab, cluster, kubeconfig):
    role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
            "metadata": {"name": READER_ROLE},
            "rules": [{"nonResourceURLs": [PPROF_INDEX], "verbs": ["get"]}]}
    binding = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
               "metadata": {"name": READER_ROLE},
               "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": READER_ROLE},
               "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": FIXTURE_READER}]}
    api_request(lab, cluster, kubeconfig, role)
    api_request(lab, cluster, kubeconfig, binding)
    # API persistence and RBAC informer visibility need not be simultaneous.
    deadline = monotonic() + 12
    while monotonic() < deadline:
        if access_review(lab, cluster, kubeconfig, "get", PPROF_INDEX) is True:
            return
        sleep(0.25)
    lab.block("The index grant was not visible to the live authorizer within 12 seconds")


def access_review(lab, cluster, kubeconfig, verb, path):
    review = api_request(lab, cluster, kubeconfig, {
        "apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
        "spec": {"user": FIXTURE_READER, "groups": ["system:authenticated"],
                 "nonResourceAttributes": {"path": path, "verb": verb}},
    })
    status = review.get("status", {})
    if status.get("evaluationError") or type(status.get("allowed")) is not bool:
        lab.block("SubjectAccessReview did not return an authoritative decision")
    return status["allowed"]


def check_adjacent_authorization(lab, cluster, kubeconfig):
    decisions = {f"{verb} {path}": access_review(lab, cluster, kubeconfig, verb, path) is False
                 for verb, path in DIAGNOSTIC_PERMISSIONS}
    lab.check("green", "The index reader grant leaves every tested adjacent diagnostic permission unauthorized",
              all(decisions.values()), {"denied_by_authorizer": decisions, "diagnostic_handlers_invoked": False})


def run(lab):
    check_profile(lab, lab.cluster, lab.kubeconfig, "true", 200)
    before = authenticated_status(lab, lab.kubeconfig, lab.cluster, PPROF_INDEX, fixture_reader=True)
    lab.check("red", "A newly authenticated reader cannot access the enabled index before a specific grant",
              before == 403, {"http_status": before})
    grant_index_reader(lab, lab.cluster, lab.kubeconfig)
    allowed = authenticated_status(lab, lab.kubeconfig, lab.cluster, PPROF_INDEX, fixture_reader=True)
    lab.check("positive", "The approved exact GET rule allows the reader into the enabled index",
              allowed == 200, {"http_status": allowed})
    check_adjacent_authorization(lab, lab.cluster, lab.kubeconfig)
    with owned_profile(lab, "profiling-off", "false") as (cluster, kubeconfig):
        check_profile(lab, cluster, kubeconfig, "false", 404)
        grant_index_reader(lab, cluster, kubeconfig)
        blocked = authenticated_status(lab, kubeconfig, cluster, PPROF_INDEX, fixture_reader=True)
        lab.check("green", "The authorized reader still gets HTTP 404 after profiling is disabled",
                  blocked == 404, {"http_status": blocked})
