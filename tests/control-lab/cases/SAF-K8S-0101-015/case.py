"""Exercise the API server webhook endpoint identity and failure behavior."""
import base64
import http.client
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.parse


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
WEBHOOK_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-test"
IDENTITY = "system:serviceaccount:saf-test:webhook-probe"
CONFIGMAP = "webhook-probe"
TIMEOUT = 10
CREDENTIALS_DIR = None
WEBHOOK_HOST = None
SCOPE = (
    "Self-managed Kubernetes v1.36.1 kind API server using structured AuthorizationConfiguration. "
    "The same real, minimally scoped service-account GET of one synthetic ConfigMap is authorized "
    "by a local mTLS webhook when endpoint CA validation succeeds, and fails closed when the "
    "webhook kubeconfig trusts an unrelated ephemeral CA. Server name validation, API-server client "
    "certificate authentication, webhook request attributes, and a normal cluster-admin read are "
    "observed. This does not establish hosted-provider controls or production review governance."
)


def checked(lab, *args, timeout=TIMEOUT + 5):
    return lab.command(*args, timeout=timeout)


def write_certificates(lab, directory, hostname):
    """Create fresh local CA, server, client, and wrong-trust CA credentials."""
    def openssl(*args):
        # openssl stdout/stderr are discarded; no key or certificate contents enter logs.
        result = subprocess.run(["openssl", *args], env=lab.env, capture_output=True,
                                text=True, timeout=TIMEOUT, check=False)
        if result.returncode:
            lab.block("Could not create synthetic webhook TLS credentials")

    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-keyout", str(directory / "ca.key"), "-out", str(directory / "ca.crt"),
            "-subj", "/CN=saf-ephemeral-webhook-ca",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash")
    leaf_extensions = ("[leaf]\nbasicConstraints=critical,CA:FALSE\n"
                       "authorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n")
    (directory / "server.ext").write_text(
        leaf_extensions + f"subjectAltName=DNS:{hostname}\nextendedKeyUsage=serverAuth\n"
    )
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout",
            str(directory / "server.key"), "-out", str(directory / "server.csr"),
            "-subj", "/CN=authz-webhook")
    openssl("x509", "-req", "-in", str(directory / "server.csr"), "-CA",
            str(directory / "ca.crt"), "-CAkey", str(directory / "ca.key"),
            "-CAcreateserial", "-days", "1", "-extfile", str(directory / "server.ext"),
            "-extensions", "leaf",
            "-out", str(directory / "server.crt"))
    (directory / "client.ext").write_text(leaf_extensions + "extendedKeyUsage=clientAuth\n")
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout",
            str(directory / "client.key"), "-out", str(directory / "client.csr"),
            "-subj", "/CN=saf-apiserver")
    openssl("x509", "-req", "-in", str(directory / "client.csr"), "-CA",
            str(directory / "ca.crt"), "-CAkey", str(directory / "ca.key"),
            "-CAcreateserial", "-days", "1", "-extfile", str(directory / "client.ext"),
            "-extensions", "leaf",
            "-out", str(directory / "client.crt"))
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-keyout", str(directory / "wrong-ca.key"), "-out", str(directory / "wrong-ca.crt"),
            "-subj", "/CN=saf-intentionally-untrusted-ca",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    # Retain only the endpoint/client keys needed for this run; discard CA keys
    # and signing requests as soon as the ephemeral leaf certificates exist.
    for name in ("ca.key", "wrong-ca.key", "server.csr", "client.csr", "ca.srl"):
        path = directory / name
        if path.exists():
            path.unlink()
    for name in ("server.key", "client.key"):
        (directory / name).chmod(0o400)


def authz_files(directory, trusted_ca, hostname):
    api = directory / "apiserver"
    api.mkdir(mode=0o700, exist_ok=True)
    for name in (trusted_ca, "client.crt", "client.key"):
        shutil.copy2(directory / name, api / name)
    kubeconfig = api / "webhook-kubeconfig.yaml"
    endpoint = f"https://{hostname}:9443/authorize"
    kubeconfig.write_text(
        "apiVersion: v1\nkind: Config\ncurrent-context: webhook\n"
        "clusters:\n- name: webhook\n  cluster:\n"
        f"    server: {endpoint}\n    certificate-authority: /etc/kubernetes/webhook/{trusted_ca}\n"
        "users:\n- name: apiserver\n  user:\n"
        "    client-certificate: /etc/kubernetes/webhook/client.crt\n"
        "    client-key: /etc/kubernetes/webhook/client.key\n"
        "contexts:\n- name: webhook\n  context:\n"
        "    cluster: webhook\n    user: apiserver\n"
    )
    config = api / "authorization.yaml"
    config.write_text(
        "apiVersion: apiserver.config.k8s.io/v1\nkind: AuthorizationConfiguration\n"
        "authorizers:\n"
        "- type: Node\n  name: node\n"
        "- type: RBAC\n  name: rbac\n"
        "- type: Webhook\n  name: synthetic-webhook\n  webhook:\n"
        "    subjectAccessReviewVersion: v1\n    timeout: 2s\n"
        "    cacheAuthorizedRequests: false\n    cacheUnauthorizedRequests: false\n"
        "    failurePolicy: Deny\n    matchConditionSubjectAccessReviewVersion: v1\n"
        "    matchConditions:\n"
        f'    - expression: "request.user == \x27{IDENTITY}\x27 && has(request.resourceAttributes)"\n'
        f'    - expression: "request.resourceAttributes.verb == \x27get\x27 && request.resourceAttributes.namespace == \x27{NAMESPACE}\x27 && request.resourceAttributes.resource == \x27configmaps\x27 && request.resourceAttributes.name == \x27{CONFIGMAP}\x27"\n'
        "    connectionInfo:\n      type: KubeConfigFile\n"
        "      kubeConfigFile: /etc/kubernetes/webhook/webhook-kubeconfig.yaml\n"
    )


def kind_config(directory):
    return (
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n"
        "nodes:\n- role: control-plane\n"
        "  extraMounts:\n  - hostPath: " + json.dumps(str(directory / "apiserver")) + "\n"
        "    containerPath: /etc/kubernetes/webhook\n    readOnly: true\n"
        "    selinuxRelabel: false\n"
        "kubeadmConfigPatches:\n- |\n"
        "  apiVersion: kubeadm.k8s.io/v1beta4\n  kind: ClusterConfiguration\n"
        "  apiServer:\n    extraArgs:\n"
        "    - name: authorization-config\n      value: /etc/kubernetes/webhook/authorization.yaml\n"
        "    extraVolumes:\n"
        "    - name: webhook-config\n      hostPath: /etc/kubernetes/webhook\n"
        "      mountPath: /etc/kubernetes/webhook\n      readOnly: true\n"
        "      pathType: Directory\n"
    )


def run_webhook(lab, directory, name, hostname):
    # Private to the kind Docker network: no published host port or external bind.
    certificates = ("ca.crt", "server.crt", "server.key")
    mounts = tuple(arg for filename in certificates for arg in (
        "--mount", f"type=bind,src={directory / filename},dst=/case/{filename},readonly"))
    return checked(
        lab, "docker", "run", "--detach", "--rm", "--name", name,
        "--network", "kind", "--network-alias", hostname,
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", f"{os.getuid()}:{os.getgid()}",
        *mounts,
        "--mount", f"type=bind,src={Path(__file__).with_name('webhook_server.py')},dst=/webhook_server.py,readonly",
        WEBHOOK_IMAGE, "python", "/webhook_server.py", timeout=120,
    )


def cleanup_container(lab, name):
    lab.command("docker", "rm", "--force", name, timeout=20, allow_failure=True)
    remaining = checked(lab, "docker", "ps", "-aq", "--filter", f"name=^/{name}$")
    if remaining.stdout.strip():
        lab.block("An owned webhook container remains after cleanup")


def cluster_cli(lab, kubeconfig, cluster, *args, timeout=TIMEOUT + 5, allow_failure=False):
    return lab.command(
        "kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
        "--namespace", NAMESPACE, f"--request-timeout={TIMEOUT - 2}s", *args,
        timeout=timeout, allow_failure=allow_failure,
    )


def make_fixture(lab, kubeconfig, cluster):
    cluster_cli(lab, kubeconfig, cluster, "create", "serviceaccount", "webhook-probe")
    cluster_cli(lab, kubeconfig, cluster, "create", "configmap", CONFIGMAP,
                "--from-literal=fixture=synthetic-owned-value")


def read_token(lab, kubeconfig, cluster):
    # Token output is held only in memory and never passed through Lab.command/logs.
    args = ["kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
            "--namespace", NAMESPACE, "create", "token", "webhook-probe", "--duration=10m"]
    try:
        result = subprocess.run(args, env=lab.env, capture_output=True, text=True,
                                timeout=TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("Could not obtain short-lived synthetic service-account credential")
    if result.returncode or not result.stdout.strip():
        lab.block("Could not obtain short-lived synthetic service-account credential")
    return result.stdout.strip()


def kube_endpoint(lab, kubeconfig, cluster):
    def value(path):
        result = subprocess.run(
            ["kubectl", "config", "view", "--kubeconfig", str(kubeconfig), "--raw",
             "--context", f"kind-{cluster}", "--minify", "-o", f"jsonpath={path}"],
            env=lab.env, capture_output=True, text=True, timeout=TIMEOUT, check=False,
        )
        if result.returncode:
            lab.block("Could not inspect selected case kubeconfig")
        return result.stdout.strip()
    try:
        server = urllib.parse.urlsplit(value("{.clusters[0].cluster.server}"))
        ca = base64.b64decode(value("{.clusters[0].cluster.certificate-authority-data}"), validate=True)
        if server.scheme != "https" or server.hostname not in ("127.0.0.1", "::1", "localhost") or not server.port:
            lab.block("Refusing an API endpoint outside the local runner-owned loopback")
        return server.hostname, server.port, ca
    except (ValueError, TypeError):
        lab.block("Invalid runner kubeconfig API endpoint or CA")


def api_get(lab, kubeconfig, cluster, token, path):
    host, port, ca = kube_endpoint(lab, kubeconfig, cluster)
    context = ssl.create_default_context(cadata=ca.decode("ascii"))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    conn = http.client.HTTPSConnection(host, port, timeout=TIMEOUT, context=context)
    try:
        conn.request("GET", path, headers={"Authorization": f"Bearer {token}", "Connection": "close"})
        response = conn.getresponse()
        status = response.status
        # Drain a bounded response without retaining dynamic error bodies.
        body = response.read(65536)
        try:
            result = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            result = {}
        marker = status == 200 and result.get("data", {}).get("fixture") == "synthetic-owned-value"
        message = (result.get("message") or body.decode("utf-8", "replace")).lower()
        categories = ("x509", "unknown authority", "no such host", "connection refused",
                      "outside synthetic exact-read policy", "cannot get")
        return status, marker, [reason for reason in categories if reason in message]
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        lab.block(f"Owned API read did not return an HTTP response: {type(error).__name__}")
    finally:
        conn.close()


def collect_safe_webhook_evidence(lab, name):
    result = lab.command("docker", "logs", name, timeout=TIMEOUT, allow_failure=True)
    # docker logs are synthetic SAR metadata only; parse fixed values and discard raw text.
    rows = []
    for line in result.stdout.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("event") in {"sar", "client-rejected-server-cert", "ready", "unexpected-sar"}:
            rows.append(row)
    return rows


def assert_profile(lab, kubeconfig, cluster, expected_status, container_name, *, expect_webhook):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if any(row["event"] == "ready" for row in collect_safe_webhook_evidence(lab, container_name)):
            break
        time.sleep(1)
    else:
        lab.block("The pinned synthetic webhook did not report startup")

    make_fixture(lab, kubeconfig, cluster)
    token = read_token(lab, kubeconfig, cluster)
    status, marker, denial_categories = api_get(
        lab, kubeconfig, cluster, token, f"/api/v1/namespaces/{NAMESPACE}/configmaps/{CONFIGMAP}")
    observations = collect_safe_webhook_evidence(lab, container_name)
    lab.check(
        "green" if expected_status == 200 else "red",
        "Same owned service-account ConfigMap GET has the expected webhook trust outcome",
        status == expected_status and marker == expect_webhook
        and (expect_webhook or {"x509", "unknown authority"} <= set(denial_categories)),
        {"method": "GET", "path": f"/api/v1/namespaces/{NAMESPACE}/configmaps/{CONFIGMAP}",
         "identity": IDENTITY, "http_status": status, "marker_observed": marker,
         "denial_categories": denial_categories,
         "webhook_events": sorted({row["event"] for row in observations}),
         "webhook_server_ca": "ephemeral issuing CA" if expect_webhook else "wrong ephemeral CA",
         "api_server_client_certificate": "saf-apiserver"},
    )
    matched = [row for row in observations if row.get("identity") == IDENTITY]
    if expect_webhook:
        proof = any(row.get("client_cn") == "saf-apiserver" and row.get("verb") == "get"
                    and row.get("resource") == "configmaps" and row.get("namespace") == NAMESPACE
                    and row.get("name") == CONFIGMAP and row.get("allowed") is True for row in matched)
        lab.check("positive", "Webhook received the exact SAR over mutually authenticated TLS",
                  proof, {"observed_client_certificate": "saf-apiserver" if proof else "not observed",
                          "request": "GET named ConfigMap", "sar": "authorization.k8s.io/v1"})
    else:
        client_rejection = any(row.get("event") == "client-rejected-server-cert"
                               for row in observations)
        lab.check("positive", "Wrong server trust failed during TLS before the webhook accepted an SAR",
                  client_rejection and not matched,
                  {"client_certificate_alert_observed": client_rejection,
                   "webhook_received_fixture_sar": bool(matched),
                               "failure_policy": "Deny"})
    read = cluster_cli(lab, kubeconfig, cluster, "get", "namespace", NAMESPACE, "-o", "name")
    lab.check("positive", "Unaffected authorized namespace read succeeds",
              read.stdout.strip() == f"namespace/{NAMESPACE}",
              {"request": "GET namespace saf-test", "result": "allowed"})


def run(lab):
    directory = CREDENTIALS_DIR
    hostname = WEBHOOK_HOST
    if directory is None or not directory.is_dir() or hostname is None:
        lab.block("Correct-trust credentials were not prepared for the runner-owned profile")
    (directory / "wrong-ca.crt").chmod(0o444)
    (directory / "ca.crt").chmod(0o444)
    (directory / "client.crt").chmod(0o444)
    (directory / "server.crt").chmod(0o444)
    name = f"{lab.cluster}-authz-webhook"
    run_webhook(lab, directory, name, hostname)
    try:
        # Correct-trust runner-owned profile: built with prepare_kind below.
        assert_profile(lab, lab.kubeconfig, lab.cluster, 200, name, expect_webhook=True)
    finally:
        cleanup_container(lab, name)

    # The API-server config is static-pod bootstrap state. Use a second isolated
    # disposable cluster to compare the identical API request under wrong trust.
    cluster = f"{lab.cluster}-badtrust"
    listed = lab.command("kind", "get", "clusters")
    if cluster in listed.stdout.splitlines():
        lab.block("Refusing to reuse a pre-existing wrong-trust cluster name")
    with tempfile.TemporaryDirectory(prefix="saf-authz-webhook-badtrust-") as temp:
        bad_directory = Path(temp)
        for filename in ("ca.crt", "wrong-ca.crt", "client.crt", "client.key",
                         "server.crt", "server.key"):
            shutil.copy2(directory / filename, bad_directory / filename)
        authz_files(bad_directory, "wrong-ca.crt", hostname)
        kubeconfig = bad_directory / "badtrust-kubeconfig"
        config = bad_directory / "badtrust-kind.yaml"
        config.write_text(kind_config(bad_directory))
        owned = False
        bad_name = f"{cluster}-webhook"
        try:
            owned = True
            lab.command("kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                        "--config", str(config), "--kubeconfig", str(kubeconfig),
                        "--wait", "90s", timeout=480)
            lab.command("kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
                        "create", "namespace", NAMESPACE, timeout=45)
            run_webhook(lab, bad_directory, bad_name, hostname)
            try:
                assert_profile(lab, kubeconfig, cluster, 500, bad_name, expect_webhook=False)
            finally:
                cleanup_container(lab, bad_name)
        finally:
            if owned:
                deleted = lab.command("kind", "delete", "cluster", "--name", cluster,
                                      "--kubeconfig", str(kubeconfig), timeout=90,
                                      allow_failure=True)
                if deleted.returncode:
                    lab.block("Could not confirm cleanup of wrong-trust kind cluster")

def prepare_kind(_lab, temporary):
    """Configure the runner-owned cluster with the correctly trusted authz chain."""
    global CREDENTIALS_DIR, WEBHOOK_HOST
    directory = Path(temporary) / "authz-webhook-files"
    directory.mkdir(mode=0o700)
    CREDENTIALS_DIR = directory
    WEBHOOK_HOST = f"authz-webhook-{_lab.cluster}"
    write_certificates(_lab, directory, WEBHOOK_HOST)
    authz_files(directory, "ca.crt", WEBHOOK_HOST)
    path = Path(temporary) / "authz-webhook-kind.yaml"
    path.write_text(kind_config(directory))
    return path
