"""Exercise etcd client and peer TLS authentication in a fresh Kind cluster."""
import importlib.util
import json
from ipaddress import ip_address
from pathlib import Path
import re
import subprocess


SCOPE = (
    "Owned three-control-plane Kind v1.36.1. The designated first member retains the "
    "client and peer certificate authentication checks, standard health-check client "
    "and readiness comparisons. A separate topology comparison verifies trusted peer "
    "TLS across three exact member pairs and cert-less refusal on each member. The "
    "cross-member comparison uses TLS handshakes without application requests."
)


HERE = Path(__file__).resolve().parent
PEER_SPEC = importlib.util.spec_from_file_location("peer_topology", HERE / "peer_topology.py")
peer_topology = importlib.util.module_from_spec(PEER_SPEC)
PEER_SPEC.loader.exec_module(peer_topology)

ETCD_CERT_DIR = "/etc/kubernetes/pki/etcd"
EXPECTED_ALERT = "certificate required"


def _flag(command, name):
    prefix = f"--{name}="
    values = [arg[len(prefix):] for arg in command if arg.startswith(prefix)]
    if len(values) != 1:
        raise AssertionError(f"expected one --{name}=... argument, found {len(values)}")
    return values[0]


def _run_tls_probe(lab, node, address, port):
    """Run a safe, cert-less TLS handshake and retain only stable receipt fields."""
    args = [
        "docker", "exec", node, "timeout", "8", "openssl", "s_client",
        "-connect", f"{address}:{port}", "-tls1_3", "-brief", "-ign_eof",
        "-CAfile", f"{ETCD_CERT_DIR}/ca.crt", "-verify_return_error",
        "-verify_ip", address,
    ]
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=12,
                                env=lab.env, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"bounded TLS probe failed to run on the Kind node: {error}") from error

    transcript = (result.stdout + "\n" + result.stderr).lower()
    verified = "verification: ok" in transcript
    alert = EXPECTED_ALERT if re.search(r"alert\s+certificate required", transcript) else None
    rejected = result.returncode != 0 and alert is not None
    # Keep a small, stable receipt. Full OpenSSL output is intentionally discarded.
    return {
        "port": port,
        "protocol": "TLSv1.3" if "protocol version: tlsv1.3" in transcript else None,
        "server_verified": verified,
        "rejection_alert": alert,
        "client_certificate_rejected": rejected,
        "exit_nonzero": result.returncode != 0,
    }


def run(lab):
    cluster = lab.cluster
    node = f"{cluster}-control-plane"

    # Read the running static Pod manifest; this is a live configuration check,
    # not an inference from Kind or kubeadm defaults.
    pods = json.loads(lab.kubectl(
        "get", "pods", "-n", "kube-system", "-l", "component=etcd",
        "--field-selector", f"spec.nodeName={node}", "-o", "json").stdout)["items"]
    if len(pods) != 1:
        lab.block("Expected exactly one etcd Pod on the designated first control plane")
    pod = pods[0]
    etcd_pod = pod["metadata"]["name"]
    command = pod["spec"]["containers"][0]["command"]
    client_auth = _flag(command, "client-cert-auth")
    peer_auth = _flag(command, "peer-client-cert-auth")
    client_urls = _flag(command, "listen-client-urls").split(",")
    peer_urls = _flag(command, "listen-peer-urls").split(",")
    if client_auth != "true" or peer_auth != "true":
        lab.check("red", "kubeadm etcd client and peer cert-auth flags are enabled",
                  False, f"client-cert-auth={client_auth}; peer-client-cert-auth={peer_auth}")
    if not any(url.startswith("https://") and url.endswith(":2379") for url in client_urls):
        raise RuntimeError(f"expected an HTTPS etcd client listener on port 2379; found {client_urls}")
    if not any(url.startswith("https://") and url.endswith(":2380") for url in peer_urls):
        raise RuntimeError(f"expected an HTTPS etcd peer listener on port 2380; found {peer_urls}")
    lab.check("green", "live etcd manifest enables certificate authentication on both TLS channels",
              True, "client-cert-auth=true; peer-client-cert-auth=true; HTTPS 2379/2380")

    # Two deterministic receipts compare a no-client-certificate probe against
    # the expected TLS-layer rejection on each distinct etcd listener.
    node_obj = json.loads(lab.kubectl("get", "node", node, "-o", "json").stdout)
    peer_ip = str(ip_address(next(a["address"] for a in node_obj["status"]["addresses"]
                                  if a["type"] == "InternalIP")))
    for phase_name, address, port in (("client", "127.0.0.1", 2379), ("peer", peer_ip, 2380)):
        receipt = _run_tls_probe(lab, node, address, port)
        expected = {
            "port": port,
            "protocol": "TLSv1.3",
            "server_verified": True,
            "rejection_alert": EXPECTED_ALERT,
            "client_certificate_rejected": True,
            "exit_nonzero": True,
        }
        lab.check("red", f"cert-less {phase_name} TLS handshake is rejected after server verification",
                  receipt == expected,
                  json.dumps(receipt, sort_keys=True, separators=(",", ":")))

    # Use only kubeadm's existing local health-check certificate and key. The
    # command output is a health receipt; no certificate or key contents are read.
    health = lab.kubectl(
        "exec", "-n", "kube-system", etcd_pod, "--", "etcdctl",
        f"--endpoints=https://127.0.0.1:2379",
        f"--cacert={ETCD_CERT_DIR}/ca.crt",
        f"--cert={ETCD_CERT_DIR}/healthcheck-client.crt",
        f"--key={ETCD_CERT_DIR}/healthcheck-client.key",
        "endpoint", "health", timeout=25,
    ).stdout.strip()
    lab.check("green", "stock etcd health-check client certificate completes a verified TLS health read",
              "is healthy: successfully committed proposal" in health,
              "healthy health-check-client on https://127.0.0.1:2379")

    peer = lab.command("docker", "exec", node, "bash", "-ceu",
        'printf "" | timeout 8 openssl s_client -connect "$1:2380" -tls1_2 -brief '
        '-CAfile /etc/kubernetes/pki/etcd/ca.crt -verify_return_error -verify_ip "$1" '
        '-cert /etc/kubernetes/pki/etcd/peer.crt -key /etc/kubernetes/pki/etcd/peer.key',
        "bash", peer_ip, timeout=15, allow_failure=True)
    verified = "Verification: OK" in peer.stderr + peer.stdout
    lab.check("positive", "Trusted peer certificate completes the verified peer TLS handshake",
              peer.returncode == 0 and verified, {"certificate_verified": verified, "success": peer.returncode == 0})

    api_ready = lab.kubectl("get", "--raw=/readyz", timeout=25).stdout.strip()
    lab.check("positive", "Kubernetes API readiness read remains available",
              api_ready == "ok", f"/readyz={api_ready!r}")

    peer_topology.run(lab)
