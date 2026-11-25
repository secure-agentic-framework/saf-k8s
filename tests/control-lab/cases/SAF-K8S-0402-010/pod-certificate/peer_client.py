"""Run in A's owned Pod: use its projected credential against B's NodePort."""
import json
import os
from pathlib import Path
import socket
import ssl
import time

from cryptography import x509
from cryptography.x509.oid import ExtensionOID


BUNDLE = "/var/run/pod-identity/credential.pem"
TRUST_B = "/var/run/peer-trust/domain-b.pem"
PORT = 30443
SNI = "peer-b.fixture.invalid"
EXPECTED_SERVER_URI = "spiffe://domain-b.fixture.invalid/ns/saf-0402-010-peer/sa/peer-server"
EXPECTED_ALLOW = b"ALLOW\n"


def run():
    node_ip = os.environ.get("PEER_NODE_IP", "")
    if not node_ip or ":" in node_ip or any(ch not in "0123456789." for ch in node_ip):
        print(json.dumps({"node_ip_configured": False, "mutual_tls_allowed": False}), flush=True)
        return 1
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline and not all(Path(path).is_file() and Path(path).stat().st_size
                                                    for path in (BUNDLE, TRUST_B)):
        time.sleep(1)
    if not all(Path(path).is_file() and Path(path).stat().st_size for path in (BUNDLE, TRUST_B)):
        print(json.dumps({"node_ip_configured": True, "network_reachable": False,
                          "mutual_tls_allowed": False}), flush=True)
        return 1
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=TRUST_B)
    context.check_hostname = True
    context.load_cert_chain(BUNDLE)
    result = {"node_ip_configured": True, "network_reachable": False, "tls_established": False,
              "server_sni_verified": False, "server_uri_verified": False,
              "server_authorized_client": False}
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            raw = socket.create_connection((node_ip, PORT), timeout=4)
            result["network_reachable"] = True
            with raw:
                with context.wrap_socket(raw, server_hostname=SNI) as tls:
                    result["tls_established"] = True
                    result["server_sni_verified"] = tls.server_hostname == SNI
                    cert = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
                    uris = cert.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(
                            x509.UniformResourceIdentifier)
                    result["server_uri_verified"] = uris == [EXPECTED_SERVER_URI]
                    result["server_authorized_client"] = tls.recv(16) == EXPECTED_ALLOW
                    break
        except ssl.SSLError:
            break
        except (OSError, ValueError):
            time.sleep(2)
    result["mutual_tls_allowed"] = all(result[key] for key in (
        "tls_established", "server_sni_verified", "server_uri_verified", "server_authorized_client"))
    print(json.dumps(result, sort_keys=True), flush=True)
    if not result["mutual_tls_allowed"]:
        return 1
    while True:
        time.sleep(60)


if __name__ == "__main__":
    raise SystemExit(run())
