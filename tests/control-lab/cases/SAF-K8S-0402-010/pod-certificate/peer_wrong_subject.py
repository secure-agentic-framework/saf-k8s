"""In B's own Pod, use its real B-issued cert to test exact peer URI policy."""
import json
import socket
import ssl
import time
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtensionOID


BUNDLE = "/var/run/pod-identity/credential.pem"
TRUST_B = "/var/run/peer-trust/domain-b.pem"
SNI = "peer-b.fixture.invalid"
SERVER_URI = "spiffe://domain-b.fixture.invalid/ns/saf-0402-010-peer/sa/peer-server"


def run():
    result = {"tls_authenticated": False, "server_identity_valid": False,
              "wrong_subject_denied": False}
    try:
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline and not all(Path(path).is_file() and Path(path).stat().st_size
                                                        for path in (BUNDLE, TRUST_B)):
            time.sleep(1)
        if not all(Path(path).is_file() and Path(path).stat().st_size for path in (BUNDLE, TRUST_B)):
            raise OSError("projected inputs unavailable")
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=TRUST_B)
        context.check_hostname = True
        context.load_cert_chain(BUNDLE)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", 8443), timeout=4) as raw:
                    with context.wrap_socket(raw, server_hostname=SNI) as tls:
                        result["tls_authenticated"] = True
                        cert = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
                        uris = cert.extensions.get_extension_for_oid(
                            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(
                                x509.UniformResourceIdentifier)
                        result["server_identity_valid"] = uris == [SERVER_URI]
                        result["wrong_subject_denied"] = tls.recv(16) == b"DENY\n"
                        break
            except (OSError, ssl.SSLError):
                time.sleep(2)
    except (OSError, ssl.SSLError, ValueError):
        pass
    print(json.dumps(result, sort_keys=True), flush=True)
    if not (result["tls_authenticated"] and result["server_identity_valid"]
            and result["wrong_subject_denied"]):
        return 1
    while True:
        time.sleep(60)


if __name__ == "__main__":
    raise SystemExit(run())
