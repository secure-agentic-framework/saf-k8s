"""Run in B's owned Pod: mTLS server with an exact A workload allow rule."""
import json
import os
from pathlib import Path
import re
import socket
import ssl
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID


BUNDLE = "/var/run/pod-identity/credential.pem"
TRUST_A = "/var/run/peer-trust/domain-a.pem"
TRUST_B = "/var/run/peer-trust/domain-b.pem"
LISTEN = ("0.0.0.0", 8443)
EXPECTED_CLIENT_URI = "spiffe://identity.example.test/ns/saf-0402-010-pcr/sa/pod-workload"
EXPECTED_CLIENT_CERTS = 3
TLS_VERSION = ssl.TLSVersion.TLSv1_3


def peer_uri(tls):
    cert = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
    return cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(
            x509.UniformResourceIdentifier)


def _pem_certs(path):
    raw = open(path, "rb").read()
    return re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", raw, re.S)


def context():
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        if all(os.path.isfile(path) and os.path.getsize(path) > 0
               for path in (BUNDLE, TRUST_A, TRUST_B)):
            break
        time.sleep(1)
    else:
        raise RuntimeError("owned projected identity inputs did not become available")
    bundle = open(BUNDLE, "rb").read()
    cert_blocks = _pem_certs(BUNDLE)
    key_match = re.search(rb"-----BEGIN (?:EC |RSA |)PRIVATE KEY-----.*?-----END (?:EC |RSA |)PRIVATE KEY-----",
                          bundle, re.S)
    if not key_match or not cert_blocks:
        raise RuntimeError("owned projected server identity is incomplete")
    key = serialization.load_pem_private_key(key_match.group(0), password=None)
    leaf = x509.load_pem_x509_certificate(cert_blocks[0])
    ca = x509.load_pem_x509_certificate(cert_blocks[1])
    key_der = key.public_key().public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
    cert_der = leaf.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    usages = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    leaf_usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    ca_ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    leaf_aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    roots_b = [x509.load_pem_x509_certificate(item) for item in _pem_certs(TRUST_B)]
    roots_a = [x509.load_pem_x509_certificate(item) for item in _pem_certs(TRUST_A)]
    if len(roots_a) != 1 or len(roots_b) != 1:
        raise RuntimeError("fixture peer trust did not contain exactly one root per domain")
    root_subjects = [root.subject.rfc4514_string() for root in [*roots_a, *roots_b]]
    identity_ok = (key_der == cert_der and leaf.issuer == ca.subject
                   and ca.fingerprint(hashes.SHA256()) in [root.fingerprint(hashes.SHA256()) for root in roots_b]
                   and leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc
                   and "peer-b.fixture.invalid" in san.get_values_for_type(x509.DNSName)
                   and "spiffe://domain-b.fixture.invalid/ns/saf-0402-010-peer/sa/peer-server"
                       in san.get_values_for_type(x509.UniformResourceIdentifier)
                   and ExtendedKeyUsageOID.CLIENT_AUTH in usages
                   and ExtendedKeyUsageOID.SERVER_AUTH in usages
                   and leaf_usage.digital_signature
                   and leaf_aki.key_identifier == ca_ski.digest
                   and ca.subject.rfc4514_string()
                       == "CN=saf-k8s synthetic pod signer domain-b.fixture.invalid"
                   and roots_a[0].subject.rfc4514_string()
                       == "CN=saf-k8s synthetic pod signer identity.example.test"
                   and roots_b[0].subject.rfc4514_string()
                       == "CN=saf-k8s synthetic pod signer domain-b.fixture.invalid"
                   and len(set(root_subjects)) == 2
                   and all(root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                           for root in [*roots_a, *roots_b]))
    if not identity_ok:
        raise RuntimeError("owned projected identity or peer trust did not match fixture policy")
    print(json.dumps({"server_identity_valid": True, "trust_roots_selected": 2}), flush=True)
    result = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    result.minimum_version = TLS_VERSION
    result.maximum_version = TLS_VERSION
    result.load_cert_chain(BUNDLE)
    result.load_verify_locations(cafile=TRUST_A)
    # The local B root is trusted only so the B-issued negative subject control
    # completes TLS and exercises the separate URI authorization decision.
    result.load_verify_locations(cafile=TRUST_B)
    result.verify_mode = ssl.CERT_REQUIRED
    return result


def run():
    tls_context = context()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(LISTEN)
        listener.listen(EXPECTED_CLIENT_CERTS)
        listener.settimeout(1)
        Path("/run/saf-peer-ready/ready").write_text("ready\n")
        while True:
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            observation = {"tls_authenticated": False, "subject_allowed": False,
                           "unknown_client_issuer": False}
            try:
                with conn:
                    with tls_context.wrap_socket(conn, server_side=True) as tls:
                        observation["tls_authenticated"] = True
                        observation["subject_allowed"] = peer_uri(tls) == [EXPECTED_CLIENT_URI]
                        tls.sendall(b"ALLOW\n" if observation["subject_allowed"] else b"DENY\n")
            except ssl.SSLCertVerificationError as error:
                observation["unknown_client_issuer"] = error.verify_code in {18, 19, 20, 21}
            except ssl.SSLError:
                observation["tls_authenticated"] = False
            print(json.dumps(observation, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
