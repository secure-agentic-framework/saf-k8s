"""Compare anonymous health access with anonymous authentication disabled."""
import base64
from contextlib import contextmanager
import http.client
import ipaddress
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import urllib.parse


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
NAMESPACE = "saf-test"
TIMEOUT = 8
SCOPE = (
    "A standard unauthenticated GET to /livez over HTTPS on the case-owned "
    "kind API-server IP loopback, trusting only that profile's CA, compared "
    "between the runner's default anonymous-auth profile and a separate profile "
    "configured with --anonymous-auth=false. Authorized /livez and ordinary "
    "namespace API operations are checked in each profile. No credentials are "
    "loaded by the anonymous client. Managed-provider behavior is not exercised."
)


def selected_value(lab, kubeconfig, cluster, jsonpath):
    """Read only a selected public kubeconfig field without logging output."""
    expected_context = f"kind-{cluster}"
    result = subprocess.run(
        ["kubectl", "config", "view", "--kubeconfig", str(kubeconfig),
         "--context", expected_context, "--minify", "--raw", "-o",
         f"jsonpath={jsonpath}"],
        env=lab.env, capture_output=True, text=True, timeout=TIMEOUT, check=False,
    )
    if result.returncode:
        lab.block(f"Could not read selected public kubeconfig field for {expected_context}")
    return result.stdout.strip()


def loopback_endpoint_and_ca(lab, kubeconfig, cluster):
    """Validate the exact kind context and return its HTTPS loopback and CA."""
    expected_context = f"kind-{cluster}"
    context = selected_value(lab, kubeconfig, cluster, "{.contexts[0].name}")
    server = selected_value(lab, kubeconfig, cluster, "{.clusters[0].cluster.server}")
    ca_data = selected_value(
        lab, kubeconfig, cluster, "{.clusters[0].cluster.certificate-authority-data}",
    )
    try:
        parsed = urllib.parse.urlsplit(server)
        address = parsed.hostname
        port = parsed.port
        loopback = ipaddress.ip_address(address).is_loopback
        ca_pem = base64.b64decode(ca_data, validate=True)
        ca_text = ca_pem.decode("ascii")
    except (ValueError, TypeError, UnicodeDecodeError) as error:
        lab.block(f"Invalid HTTPS endpoint or CA for {expected_context}: {type(error).__name__}")
    if context != expected_context:
        lab.block(f"Expected context {expected_context}, got {context!r}")
    if parsed.scheme != "https" or not loopback or not port:
        lab.block(f"Refusing non-HTTPS or non-loopback endpoint for {expected_context}")
    return address, port, ca_text


def anonymous_get_livez(lab, kubeconfig, cluster):
    """Send exactly GET /livez with server CA validation and no client identity."""
    address, port, ca_text = loopback_endpoint_and_ca(lab, kubeconfig, cluster)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=ca_text)
    connection = http.client.HTTPSConnection(
        address, port, timeout=TIMEOUT, context=context,
    )
    try:
        # Deliberately no client certificate, bearer token, Authorization header,
        # or any request beyond this standard health GET.
        connection.request("GET", "/livez", headers={"Connection": "close"})
        response = connection.getresponse()
        status = response.status
        response.read()
        return {"method": "GET", "path": "/livez", "status": status,
                "client_certificate": "none", "authorization_header": "none",
                "tls_server_ca": "case kubeconfig CA"}
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        lab.block(f"Anonymous HTTPS GET /livez did not receive an HTTP response: {type(error).__name__}")
    finally:
        connection.close()


def authorized_health_and_api(lab, cluster, kubeconfig=None):
    """Check health and a normal namespace read through authenticated kubectl."""
    if kubeconfig is None:
        health = lab.kubectl("get", "--raw=/livez")
        namespace = lab.kubectl("get", "namespace", NAMESPACE, "-o", "name")
    else:
        prefix = ["kubectl", "--kubeconfig", str(kubeconfig), "--context",
                  f"kind-{cluster}", "--namespace", NAMESPACE,
                  f"--request-timeout={TIMEOUT}s"]
        health = lab.command(*prefix, "get", "--raw=/livez", timeout=TIMEOUT + 5)
        namespace = lab.command(*prefix, "get", "namespace", NAMESPACE, "-o", "name",
                                timeout=TIMEOUT + 5)
    return health.stdout.strip(), namespace.stdout.strip()


def profile_config():
    return (
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "kubeadmConfigPatches:\n"
        "  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: ClusterConfiguration\n"
        "    apiServer:\n"
        "      extraArgs:\n"
        "        - name: anonymous-auth\n"
        "          value: \"false\"\n"
    )


@contextmanager
def disabled_profile(lab):
    """Create and delete a collision-checked case-owned disabled-auth profile."""
    cluster = f"{lab.cluster}-anonymous-off"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block(f"Additional anonymous-auth cluster already exists: {cluster}")
    with tempfile.TemporaryDirectory(prefix="saf-anonymous-auth-") as temp:
        temp_path = Path(temp)
        kubeconfig = temp_path / "kubeconfig"
        config = temp_path / "kind.yaml"
        config.write_text(profile_config())
        owned = False
        try:
            # Include partial kind creation in cleanup ownership.
            owned = True
            lab.command("kind", "create", "cluster", "--name", cluster,
                        "--image", NODE_IMAGE, "--config", str(config),
                        "--kubeconfig", str(kubeconfig), "--wait", "90s", timeout=480)
            lab.command("kubectl", "--kubeconfig", str(kubeconfig), "--context",
                        f"kind-{cluster}", "create", "namespace", NAMESPACE,
                        timeout=45)
            yield cluster, kubeconfig
        finally:
            if owned:
                deleted = lab.command("kind", "delete", "cluster", "--name", cluster,
                                      "--kubeconfig", str(kubeconfig), timeout=90,
                                      allow_failure=True)
                if deleted.returncode:
                    lab.block(f"Could not confirm cleanup of case-owned cluster {cluster}")


def run(lab):
    # The runner-owned cluster uses the pinned Kubernetes default profile.
    baseline = anonymous_get_livez(lab, lab.kubeconfig, lab.cluster)
    lab.check(
        "red", "Default profile accepts the unauthenticated CA-verified GET /livez",
        baseline["status"] == 200, baseline,
    )
    health, namespace = authorized_health_and_api(lab, lab.cluster)
    lab.check(
        "positive", "Authorized health and ordinary namespace API reads pass in the default profile",
        health == "ok" and namespace == f"namespace/{NAMESPACE}",
        {"authorized_livez": health, "namespace_get": namespace},
    )

    with disabled_profile(lab) as (cluster, kubeconfig):
        anonymous = anonymous_get_livez(lab, kubeconfig, cluster)
        lab.check(
            "green", "--anonymous-auth=false returns actual HTTP 401 for the same unauthenticated GET /livez",
            anonymous["status"] == 401, anonymous,
        )
        health, namespace = authorized_health_and_api(lab, cluster, kubeconfig)
        lab.check(
            "positive", "Authorized health and ordinary namespace API reads still pass with anonymous auth disabled",
            health == "ok" and namespace == f"namespace/{NAMESPACE}",
            {"authorized_livez": health, "namespace_get": namespace},
        )
