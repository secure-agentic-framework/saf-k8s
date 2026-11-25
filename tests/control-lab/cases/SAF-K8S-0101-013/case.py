"""Check kubeadm API serving-certificate renewal on the owned Kind endpoint."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse


SCOPE = (
    "Kubernetes v1.36.1 kubeadm-managed API server serving certificate on the one "
    "fresh runner-owned Kind cluster's host-published loopback endpoint. The case "
    "checks the expiry of a short-lived serving leaf and renews within the fixture lead time. It observes the live process before and after "
    "the documented static-Pod restart, and validates only local TLS trust and IP "
    "identity. External PKI and other certificate paths, replicas, and deployment scheduling "
    "remain separate adoption evidence."
)

TIMEOUT = 5
RELOAD_OBSERVATION_SECONDS = 5
POD_STOP_DEADLINE = 60
POD_READY_SECONDS = 120
RENEW_BEFORE_SECONDS = 30 * 60


def endpoint_and_ca(lab):
    """Read only the endpoint and public CA from this run's generated kubeconfig."""
    context = f"kind-{lab.cluster}"
    common = (
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", context,
        "config", "view", "--minify", "-o",
    )
    server = lab.command(*common, "jsonpath={.clusters[0].cluster.server}").stdout.strip()
    encoded_ca = lab.command(
        *common, "jsonpath={.clusters[0].cluster.certificate-authority-data}", "--raw"
    ).stdout.strip()
    try:
        parsed = urllib.parse.urlsplit(server)
        address = parsed.hostname
        port = parsed.port
        ip = ipaddress.ip_address(address)
        ca_pem = base64.b64decode(encoded_ca, validate=True)
    except (ValueError, TypeError) as error:
        lab.block(f"Invalid generated Kind endpoint or CA ({type(error).__name__})")
    if parsed.scheme != "https" or not ip.is_loopback or not port or not ca_pem:
        lab.block("Refusing certificate probes except HTTPS to the generated loopback endpoint")
    return address, port, ca_pem


def tls_context(ca_pem):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cadata=ca_pem.decode("ascii"))
    return context


def probe(address, port, context, server_name):
    """Read verified leaf identity and expiry for this fixture only."""
    raw = socket.create_connection((address, port), timeout=TIMEOUT)
    tls = None
    try:
        tls = context.wrap_socket(raw, server_hostname=server_name)
        leaf = tls.getpeercert(binary_form=True)
        expiry = ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"])
        return {"verified": True, "leaf": hashlib.sha256(leaf).digest(), "expiry": expiry}
    except ssl.SSLCertVerificationError:
        return {"verified": False, "leaf": None, "certificate_rejected": True}
    except ssl.SSLError:
        return {"verified": False, "leaf": None, "certificate_rejected": False}
    finally:
        if tls is not None:
            tls.close()
        else:
            raw.close()


def make_throwaway_ca(directory):
    """Create a one-day synthetic CA used only as a deliberately wrong trust anchor."""
    key = directory / "wrong-ca.key"
    cert = directory / "wrong-ca.crt"
    result = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1", "-sha256",
         "-subj", "/CN=SAF-K8S-0101-013 throwaway wrong CA"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode:
        raise RuntimeError("Could not create the ephemeral wrong-trust-anchor fixture")
    os.chmod(key, 0o600)
    return cert.read_bytes()


def assert_owned_control_plane_node(lab):
    expected = f"{lab.cluster}-control-plane"
    nodes = lab.command("kind", "get", "nodes", "--name", lab.cluster).stdout.splitlines()
    if nodes != [expected]:
        lab.block("Expected exactly the one fresh runner-owned Kind control-plane node")
    return expected


def renew_certificate(lab, node):
    """Invoke kubeadm renewal inside only the verified runner-owned node container."""
    config_path = "/etc/kubernetes/saf-serving-renewal.yaml"
    policy = ("apiVersion: kubeadm.k8s.io/v1beta4\n"
              "kind: ClusterConfiguration\n"
              "certificateValidityPeriod: 8760h0m0s\n")
    lab.command("docker", "exec", "-i", node, "sh", "-ceu", 'cat >"$1"',
                "write-fixture-certificate-policy", config_path, payload=policy)
    result = lab.command(
        "docker", "exec", node, "kubeadm", "certs", "renew", "apiserver",
        "--config", config_path, timeout=90,
    )
    lab.check(
        "green", "kubeadm certs renew apiserver completed inside the owned control-plane node",
        result.returncode == 0, {"renewal_command_succeeded": result.returncode == 0},
    )


def restart_static_apiserver(lab, node):
    """Use kubeadm docs' manifest removal procedure and always restore the manifest."""
    manifest = "/etc/kubernetes/manifests/kube-apiserver.yaml"
    parked = "/etc/kubernetes/kube-apiserver.saf-0101-013.yaml"
    running = ("docker", "exec", node, "crictl", "ps", "--name", "kube-apiserver", "-q")
    previous = lab.command(*running).stdout.splitlines()
    if len(previous) != 1:
        lab.block("Expected one running API server in the owned node before restart")
    moved = False
    stopped = False
    try:
        lab.command(
            "docker", "exec", node, "sh", "-ec",
            f"test -f {manifest}; test ! -e {parked}; mv {manifest} {parked}",
        )
        moved = True
        deadline = time.monotonic() + POD_STOP_DEADLINE
        while time.monotonic() < deadline:
            if not lab.command(*running).stdout.strip():
                stopped = True
                break
            time.sleep(2)
    finally:
        if moved:
            lab.command(
                "docker", "exec", node, "sh", "-ec",
                f"test -f {parked}; mv {parked} {manifest}", timeout=30,
            )
    lab.check("green", "The owned static API server stopped while its manifest was parked",
              stopped, {"previous_container_stopped": stopped})
    return running, previous[0]


def wait_for_verified_endpoint(lab, address, port, ca_pem, deadline_seconds):
    context = tls_context(ca_pem)
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        try:
            result = probe(address, port, context, address)
        except (OSError, ssl.SSLError):
            time.sleep(1)
            continue
        if result["verified"]:
            ready = lab.kubectl("get", "--raw=/readyz", timeout=10, allow_failure=True)
            if ready.returncode == 0 and ready.stdout.strip() == "ok":
                return result
        time.sleep(1)
    return {"verified": False, "leaf": None}


def run(lab):
    address, port, ca_pem = endpoint_and_ca(lab)
    correct = tls_context(ca_pem)
    initial = probe(address, port, correct, address)
    lab.check(
        "positive", "The generated local API endpoint initially serves a trusted certificate for its IP",
        initial["verified"], {"same_owned_loopback_endpoint": True, "verified": initial["verified"]},
    )
    if not initial["verified"]:
        lab.block("Initial local API certificate did not validate against the fresh Kind CA")

    with tempfile.TemporaryDirectory(prefix="saf-0101-013-") as temp:
        wrong_ca = make_throwaway_ca(Path(temp))
        wrong_trust = tls_context(wrong_ca)
        wrong_ca_result = probe(address, port, wrong_trust, address)
        lab.check(
            "red", "The same local API endpoint rejects a client trust store containing only the throwaway CA",
            not wrong_ca_result["verified"] and wrong_ca_result.get("certificate_rejected", False),
            {"same_owned_loopback_endpoint": True, "certificate_rejected": not wrong_ca_result["verified"]},
        )
        wrong_identity = probe(address, port, correct, "saf-0101-013.invalid")
        lab.check(
            "red", "The same local API endpoint rejects a mismatched client-side server identity",
            not wrong_identity["verified"] and wrong_identity.get("certificate_rejected", False),
            {"same_owned_loopback_endpoint": True, "identity_mismatch_rejected": not wrong_identity["verified"]},
        )

        node = assert_owned_control_plane_node(lab)
        seconds_remaining = initial["expiry"] - time.time()
        lab.check("red", "The original verified certificate is outside the one-minute renewal comparison",
                  seconds_remaining > 60,
                  {"valid_leaf_outside_comparison_window": seconds_remaining > 60})
        lab.check("positive", "The original verified certificate is inside the fixture's thirty-minute renewal policy",
                  0 < seconds_remaining <= RENEW_BEFORE_SECONDS,
                  {"valid_leaf_due_for_renewal": 0 < seconds_remaining <= RENEW_BEFORE_SECONDS})
        renew_certificate(lab, node)

        # This short observation reports actual process behavior without assuming
        # that every API server build reloads this certificate dynamically.
        deadline = time.monotonic() + RELOAD_OBSERVATION_SECONDS
        observed_before_restart = None
        while time.monotonic() < deadline:
            try:
                current = probe(address, port, correct, address)
                if current["verified"]:
                    observed_before_restart = current
                    if current["leaf"] != initial["leaf"]:
                        break
            except (OSError, ssl.SSLError):
                pass
            time.sleep(0.5)

        (lab.evidence / "renewal-observation.json").write_text(json.dumps({
            "process_adopted_renewal_before_restart": bool(
                observed_before_restart and observed_before_restart["leaf"] != initial["leaf"]
            )
        }, indent=2) + "\n")

        running, previous = restart_static_apiserver(lab, node)
        after = wait_for_verified_endpoint(lab, address, port, ca_pem, POD_READY_SECONDS)
        current = lab.command(*running).stdout.splitlines()
        replaced = len(current) == 1 and current[0] != previous
        lab.check(
            "green", "Renewed certificate is served at the identical endpoint after the documented static-Pod restart",
            after["verified"] and after.get("leaf") != initial["leaf"] and replaced,
            {
                "same_owned_loopback_endpoint": True,
                "renewal_changed_leaf_fingerprint": after.get("leaf") != initial["leaf"],
                "trusted_identity_after_restart": after["verified"],
                "new_container_ready": replaced and after["verified"],
            },
        )
        if not after["verified"] or after.get("leaf") == initial["leaf"]:
            lab.block("Renewed API server certificate did not become validly served at the same endpoint")
        served_expiry = after["expiry"]
        moved_past_window = served_expiry > initial["expiry"] and (
            served_expiry - time.time() > RENEW_BEFORE_SECONDS
        )
        lab.check("green", "The renewed trusted leaf extends validity beyond the renewal lead time",
                  moved_past_window, {"renewed_leaf_outside_window": moved_past_window})

        post_wrong_ca = probe(address, port, wrong_trust, address)
        post_wrong_identity = probe(address, port, correct, "saf-0101-013.invalid")
        lab.check(
            "positive", "After renewal the same local endpoint still rejects wrong CA and wrong identity",
            not post_wrong_ca["verified"] and post_wrong_ca.get("certificate_rejected", False)
            and not post_wrong_identity["verified"]
            and post_wrong_identity.get("certificate_rejected", False),
            {
                "same_owned_loopback_endpoint": True,
                "wrong_ca_rejected_after_renewal": post_wrong_ca.get("certificate_rejected", False),
                "wrong_identity_rejected_after_renewal": post_wrong_identity.get("certificate_rejected", False),
            },
        )
