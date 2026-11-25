"""In B's owned Pod, send a valid A-like leaf under an untrusted synthetic CA."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import socket
import ssl
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


TRUST_B = "/var/run/peer-trust/domain-b.pem"
PEER_URI = "spiffe://identity.example.test/ns/saf-0402-010-pcr/sa/pod-workload"
TARGET = "127.0.0.1"
PORT = 8443
EXPECTED_ALERT = "TLSV1_ALERT_UNKNOWN_CA"


def _make_foreign_chain():
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_subject = x509.Name([x509.NameAttribute(
        NameOID.COMMON_NAME, "saf-k8s synthetic foreign peer issuer")])
    ca = (x509.CertificateBuilder().subject_name(ca_subject).issuer_name(ca_subject)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(minutes=5))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False,
                                       key_agreement=False, key_cert_sign=True, crl_sign=True,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                        critical=False)
          .sign(ca_key, hashes.SHA256()))

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(
                NameOID.COMMON_NAME, "saf-k8s foreign synthetic A-like workload")]))
            .issuer_name(ca.subject).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(seconds=2)).not_valid_after(now + timedelta(minutes=2))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value),
                critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(PEER_URI)]),
                           critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return leaf_key, leaf, ca_key, ca


def _structurally_valid(key, leaf, ca):
    ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    try:
        ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes,
                               ec.ECDSA(leaf.signature_hash_algorithm))
        ca.public_key().verify(ca.signature, ca.tbs_certificate_bytes,
                               ec.ECDSA(ca.signature_hash_algorithm))
        signature_ok = True
    except Exception:
        signature_ok = False
    now = datetime.now(timezone.utc)
    ca_constraints = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    return (leaf.issuer == ca.subject and ca.subject == ca.issuer
            and ca.subject.rfc4514_string() == "CN=saf-k8s synthetic foreign peer issuer"
            and ski.digest == aki.key_identifier and signature_ok
            and ca_constraints.ca and ca_constraints.path_length == 0
            and ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
            and not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            and usage.digital_signature and ExtendedKeyUsageOID.CLIENT_AUTH in
            leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            and uris == [PEER_URI] and ca.not_valid_before_utc <= now < ca.not_valid_after_utc
            and leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc
            and key.public_key().public_numbers() == leaf.public_key().public_numbers())


def _alert_class(error):
    # Record only a bounded OpenSSL reason token, never free-form exception text.
    reason = getattr(error, "reason", "")
    if reason == EXPECTED_ALERT:
        return EXPECTED_ALERT
    if isinstance(reason, str) and reason.startswith(("TLSV1_ALERT_", "SSLV3_ALERT_")):
        return "other_tls_alert"
    return "other_ssl_error"


def run():
    result = {"expected_uri": True, "foreign_chain_structurally_valid": False,
              "foreign_issuer_not_in_b_trust": False,
              "foreign_issuer_tls_rejected": False, "tls_alert_received_from_b": False,
              "tls_error_class": "not_observed", "tls_protocol_forced_v1_3": True}
    try:
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline and not (Path(TRUST_B).is_file() and Path(TRUST_B).stat().st_size):
            time.sleep(1)
        if not Path(TRUST_B).is_file() or not Path(TRUST_B).stat().st_size:
            raise OSError("projected trust unavailable")

        key, leaf, _ca_key, ca = _make_foreign_chain()
        result["foreign_chain_structurally_valid"] = _structurally_valid(key, leaf, ca)
        trusted = [x509.load_pem_x509_certificate(block)
                   for block in re.findall(
                       rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                       Path(TRUST_B).read_bytes(), re.S)]
        result["foreign_issuer_not_in_b_trust"] = (
            len(trusted) == 1
            and all(ca.fingerprint(hashes.SHA256()) != item.fingerprint(hashes.SHA256())
                    for item in trusted))
        if not result["foreign_chain_structurally_valid"]:
            result["tls_error_class"] = "fixture_chain_invalid"
            print(json.dumps(result, sort_keys=True), flush=True)
            return 1

        with tempfile.TemporaryDirectory(prefix="saf-foreign-", dir="/run/saf-negative") as temp:
            cert_path, key_path = Path(temp) / "chain.pem", Path(temp) / "client.key"
            cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM)
                                 + ca.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                    serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption()))
            cert_path.chmod(0o600)
            key_path.chmod(0o600)
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=TRUST_B)
            context.check_hostname = True
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(str(cert_path), str(key_path))
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                try:
                    raw = socket.create_connection((TARGET, PORT), timeout=3)
                except OSError:
                    time.sleep(1)
                    continue
                try:
                    with raw:
                        with context.wrap_socket(raw, server_hostname="peer-b.fixture.invalid") as tls:
                            # In TLS 1.3 the peer can reject our certificate
                            # after the client-side handshake call returns.
                            received = tls.recv(16)
                            result["tls_error_class"] = "unexpected_tls_accept" if received else "unexpected_tls_eof"
                except ssl.SSLError as error:
                    result["tls_error_class"] = _alert_class(error)
                    result["tls_alert_received_from_b"] = result["tls_error_class"] == EXPECTED_ALERT
                    result["foreign_issuer_tls_rejected"] = result["tls_alert_received_from_b"]
                break
    except (OSError, ValueError, ssl.SSLError):
        result["tls_error_class"] = "fixture_or_transport_error"
    print(json.dumps(result, sort_keys=True), flush=True)
    if not (result["foreign_chain_structurally_valid"]
            and result["foreign_issuer_not_in_b_trust"]
            and result["foreign_issuer_tls_rejected"]
            and result["tls_alert_received_from_b"]
            and result["tls_protocol_forced_v1_3"]
            and result["tls_error_class"] == EXPECTED_ALERT):
        return 1
    while True:
        time.sleep(60)


if __name__ == "__main__":
    raise SystemExit(run())
