"""Compare default and explicitly tightened kube-apiserver TLS profiles."""
import base64
from contextlib import contextmanager
import ipaddress
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path
import urllib.parse


SCOPE = (
    "TLS handshake policy and client certificate-chain validation for case-owned "
    "kind kube-apiserver client-facing loopback endpoints. A default Kubernetes "
    "profile is compared with a TLS 1.3 minimum-version profile; a separate TLS 1.2 "
    "reference profile evaluates a configured cipher allow-list. No application "
    "request or non-loopback host is contacted. Outbound kube-apiserver connections, "
    "service-specific TLS paths, and managed-provider controls are outside this case."
)

NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
APPROVED_OPENSSL_CIPHER = "ECDHE-RSA-AES128-GCM-SHA256"
EXCLUDED_OPENSSL_CIPHER = "ECDHE-RSA-CHACHA20-POLY1305"
TIMEOUT = 5


def config_value(lab, kubeconfig, cluster, jsonpath):
    """Read one selected kubeconfig value without decoding client credentials."""
    expected_context = f"kind-{cluster}"
    result = subprocess.run(
        ["kubectl", "config", "view", "--kubeconfig", str(kubeconfig),
         "--context", expected_context, "--minify", "--raw", "-o", f"jsonpath={jsonpath}"],
        env=lab.env, capture_output=True, text=True, timeout=TIMEOUT, check=False,
    )
    if result.returncode:
        lab.block(f"Could not read selected kubeconfig field for {expected_context}")
    return result.stdout.strip()


def local_endpoint_and_ca(lab, kubeconfig, cluster):
    """Read the selected cluster endpoint and CA; reject unexpected context/host."""
    expected_context = f"kind-{cluster}"
    context_name = config_value(lab, kubeconfig, cluster, "{.contexts[0].name}")
    server = config_value(lab, kubeconfig, cluster, "{.clusters[0].cluster.server}")
    ca_data = config_value(
        lab, kubeconfig, cluster,
        "{.clusters[0].cluster.certificate-authority-data}",
    )
    try:
        parsed = urllib.parse.urlsplit(server)
        address = parsed.hostname
        port = parsed.port
        ip = ipaddress.ip_address(address)
        ca_pem = base64.b64decode(ca_data, validate=True)
    except (ValueError, TypeError) as error:
        lab.block(f"Invalid endpoint or CA for {expected_context}: {type(error).__name__}")
    if context_name != expected_context:
        lab.block(f"Expected kubeconfig context {expected_context}, got {context_name!r}")
    if parsed.scheme != "https" or not ip.is_loopback or not port:
        lab.block(f"Refusing TLS probes unless {expected_context} uses an HTTPS IP loopback")
    return address, port, ca_pem


def profile_config(min_version, cipher_suites=None):
    args = [f"        - name: tls-min-version\n          value: {min_version}"]
    if cipher_suites:
        args.append(
            "        - name: tls-cipher-suites\n          value: " + ",".join(cipher_suites)
        )
    return (
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "kubeadmConfigPatches:\n"
        "  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: ClusterConfiguration\n"
        "    apiServer:\n"
        "      extraArgs:\n"
        + "\n".join(args)
        + "\n"
    )


@contextmanager
def owned_profile_cluster(lab, label, min_version, cipher_suites=None):
    """Create and always delete a uniquely named case-owned reference cluster."""
    cluster = f"{lab.cluster}-{label}"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block(f"Additional TLS profile cluster already exists: {cluster}")
    with tempfile.TemporaryDirectory(prefix=f"saf-{label}-") as temp:
        temp_path = Path(temp)
        kubeconfig = temp_path / "kubeconfig"
        config = temp_path / "kind.yaml"
        config.write_text(profile_config(min_version, cipher_suites))
        created = False
        try:
            # Mark attempted creation for cleanup even if kind fails partway through.
            created = True
            lab.command(
                "kind", "create", "cluster", "--name", cluster,
                "--image", NODE_IMAGE, "--config", str(config),
                "--kubeconfig", str(kubeconfig), "--wait", "90s", timeout=480,
            )
            yield kubeconfig, cluster
        finally:
            if created:
                result = lab.command(
                    "kind", "delete", "cluster", "--name", cluster,
                    "--kubeconfig", str(kubeconfig), timeout=90, allow_failure=True,
                )
                if result.returncode:
                    lab.block(f"Could not confirm cleanup of case-owned cluster {cluster}")


def context_for(ca_pem, *, version, cipher=None, verify=True):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = version
    ctx.maximum_version = version
    ctx.check_hostname = verify
    ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    if verify:
        ctx.load_verify_locations(cadata=ca_pem.decode("ascii"))
    if cipher:
        ctx.set_ciphers(cipher)
        if not any(row["name"] == cipher for row in ctx.get_ciphers()):
            raise RuntimeError(f"Local TLS library cannot offer requested cipher: {cipher}")
    return ctx


def handshake(address, port, context):
    """Perform one verified TLS handshake to the checked loopback IP."""
    raw = socket.create_connection((address, port), timeout=TIMEOUT)
    tls = None
    try:
        tls = context.wrap_socket(raw, server_hostname=address)
        return {"ok": True, "version": tls.version(), "cipher": tls.cipher()[0]}
    except ssl.SSLError as error:
        return {"ok": False, "reason": error.reason or type(error).__name__,
                "error": str(error)}
    finally:
        if tls is not None:
            tls.close()
        else:
            raw.close()


def server_alert(result, reason):
    return not result["ok"] and result.get("reason") == reason


def probe(lab, kubeconfig, cluster, *, version, cipher=None):
    address, port, ca_pem = local_endpoint_and_ca(lab, kubeconfig, cluster)
    try:
        ctx = context_for(ca_pem, version=version, cipher=cipher)
    except (ValueError, ssl.SSLError, RuntimeError) as error:
        lab.block(f"Local TLS library cannot construct requested client hello: {error}")
    return handshake(address, port, ctx)


def run(lab):
    if not ssl.HAS_TLSv1_3:
        lab.block("The local Python SSL library must support TLS 1.3 for this case")
    # The primary kind.yaml intentionally has no TLS policy override: it is the
    # built-in Kubernetes profile used as the actual pre-tightening baseline.
    baseline = probe(
        lab, lab.kubeconfig, lab.cluster, version=ssl.TLSVersion.TLSv1_2,
        cipher=APPROVED_OPENSSL_CIPHER,
    )
    baseline_ok = (
        baseline.get("ok")
        and baseline.get("version") == "TLSv1.2"
        and baseline.get("cipher") == APPROVED_OPENSSL_CIPHER
    )
    lab.check(
        "red", "Default Kubernetes profile accepts the approved TLS 1.2 GCM handshake",
        baseline_ok, baseline,
    )

    with owned_profile_cluster(lab, "tls13", "VersionTLS13") as (kubeconfig, cluster):
        tightened_tls12 = probe(
            lab, kubeconfig, cluster, version=ssl.TLSVersion.TLSv1_2,
            cipher=APPROVED_OPENSSL_CIPHER,
        )
        lab.check(
            "green", "TLS 1.3 minimum rejects the same TLS 1.2 GCM handshake by protocol version",
            server_alert(tightened_tls12, "TLSV1_ALERT_PROTOCOL_VERSION"),
            tightened_tls12,
        )
        tightened_tls13 = probe(
            lab, kubeconfig, cluster, version=ssl.TLSVersion.TLSv1_3,
        )
        lab.check(
            "positive", "TLS 1.3 remains usable with hostname and kubeconfig CA validation",
            tightened_tls13.get("ok") and tightened_tls13.get("version") == "TLSv1.3",
            tightened_tls13,
        )

    baseline_cipher = probe(
        lab, lab.kubeconfig, lab.cluster, version=ssl.TLSVersion.TLSv1_2,
        cipher=EXCLUDED_OPENSSL_CIPHER,
    )
    lab.check(
        "red", "The default listener can negotiate the suite excluded by the sample profile",
        baseline_cipher.get("ok") and baseline_cipher.get("version") == "TLSv1.2"
        and baseline_cipher.get("cipher") == EXCLUDED_OPENSSL_CIPHER,
        baseline_cipher,
    )

    suites = [
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    ]
    with owned_profile_cluster(
        lab, "tls12-suites", "VersionTLS12", suites,
    ) as (kubeconfig, cluster):
        excluded = probe(
            lab, kubeconfig, cluster, version=ssl.TLSVersion.TLSv1_2,
            cipher=EXCLUDED_OPENSSL_CIPHER,
        )
        lab.check(
            "green", "TLS 1.2 reference rejects a suite outside its configured GCM allow-list",
            server_alert(excluded, "SSLV3_ALERT_HANDSHAKE_FAILURE"), excluded,
        )
        approved = probe(
            lab, kubeconfig, cluster, version=ssl.TLSVersion.TLSv1_2,
            cipher=APPROVED_OPENSSL_CIPHER,
        )
        lab.check(
            "positive", "TLS 1.2 suite reference accepts the configured approved GCM suite",
            approved.get("ok") and approved.get("version") == "TLSv1.2"
            and approved.get("cipher") == APPROVED_OPENSSL_CIPHER,
            approved,
        )

    # This is a client-side trust oracle, checked against the default endpoint.
    address, port, _ = local_endpoint_and_ca(lab, lab.kubeconfig, lab.cluster)
    untrusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    untrusted.minimum_version = ssl.TLSVersion.TLSv1_2
    untrusted.maximum_version = ssl.TLSVersion.TLSv1_2
    untrusted.set_ciphers(APPROVED_OPENSSL_CIPHER)
    trust_result = handshake(address, port, untrusted)
    lab.check(
        "positive", "Client without the issuing CA rejects the case server chain",
        not trust_result["ok"]
        and trust_result.get("reason") == "CERTIFICATE_VERIFY_FAILED",
        {"oracle": "client-side certificate validation only", **trust_result},
    )
