"""Observe one kubelet credential-bundle projection and a refreshed generation.

Prints and retains only booleans. Public serial/fingerprint are inspected in
memory to compare generations, but their values and all PEM/key bytes are never
written to output or evidence.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID


BUNDLE = "/var/run/pod-identity/credential.pem"
EXPECTED_SAN = "spiffe://identity.example.test/ns/saf-0402-010-pcr/sa/pod-workload"
WAIT_SECONDS = int(os.environ.get("POD_CERT_WAIT_SECONDS", str(25 * 60)))
POLL_SECONDS = 2


def inspect(bundle: bytes):
    key_match = re.search(rb"-----BEGIN (?:EC |RSA |)PRIVATE KEY-----.*?-----END (?:EC |RSA |)PRIVATE KEY-----",
                          bundle, re.S)
    certs = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", bundle, re.S)
    if not key_match or len(certs) < 2:
        return None
    private_key = serialization.load_pem_private_key(key_match.group(0), password=None)
    leaf = x509.load_pem_x509_certificate(certs[0])
    ca = x509.load_pem_x509_certificate(certs[1])
    key_public = private_key.public_key().public_bytes(serialization.Encoding.DER,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    cert_public = leaf.public_key().public_bytes(serialization.Encoding.DER,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
    san_ok = EXPECTED_SAN in leaf.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
    eku_ok = ExtendedKeyUsageOID.CLIENT_AUTH in leaf.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage).value
    ca_ok = ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    ca_ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    leaf_aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    leaf_usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    signature_ok = leaf.issuer == ca.subject
    try:
        ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes,
                               ec.ECDSA(leaf.signature_hash_algorithm))
    except Exception:
        signature_ok = False
    now = dt.datetime.now(dt.timezone.utc)
    time_ok = leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc
    metadata = (leaf.serial_number, leaf.fingerprint(hashes.SHA256()))
    return {
        "pair_ok": key_public == cert_public,
        "chain_ok": (ca_ok and signature_ok and ca_ski.digest == leaf_aki.key_identifier
                     and leaf_usage.digital_signature
                     and ca.subject.rfc4514_string()
                     == "CN=saf-k8s synthetic pod signer identity.example.test"),
        "metadata_ok": bool(leaf.serial_number > 0 and time_ok and san_ok and eku_ok),
        "metadata": metadata,
        "public_key": cert_public,
    }


def generation():
    try:
        parent, filename = os.path.split(BUNDLE)
        link_target = os.readlink(os.path.join(parent, "..data"))
        with open(os.path.join(parent, link_target, filename), "rb") as stream:
            return link_target, stream.read()
    except (FileNotFoundError, OSError):
        return None, None


def main():
    start = time.monotonic()
    initial = None
    initial_target = None
    renewed = None
    renewed_target = None
    while time.monotonic() - start < WAIT_SECONDS:
        target, raw = generation()
        if raw:
            try:
                current = inspect(raw)
            except Exception:
                current = None
            if current and current["pair_ok"] and current["chain_ok"] and current["metadata_ok"]:
                if initial is None:
                    initial, initial_target = current, target
                    print('{"initial_projection":true}', flush=True)
                elif (target != initial_target and current["metadata"] != initial["metadata"]):
                    renewed, renewed_target = current, target
                    break
        time.sleep(POLL_SECONDS)

    result = {
        "initial_projection_valid": bool(initial),
        "initial_key_certificate_match": bool(initial and initial["pair_ok"]),
        "initial_chain_valid": bool(initial and initial["chain_ok"]),
        "initial_public_metadata_valid": bool(initial and initial["metadata_ok"]),
        "renewal_observed": bool(renewed),
        "projected_generation_changed": bool(renewed and renewed_target != initial_target),
        "public_certificate_metadata_changed": bool(renewed and renewed["metadata"] != initial["metadata"]),
        "renewed_key_certificate_match": bool(renewed and renewed["pair_ok"]),
        "renewed_chain_valid": bool(renewed and renewed["chain_ok"]),
        "renewed_public_metadata_valid": bool(renewed and renewed["metadata_ok"]),
        "public_key_changed": bool(renewed and renewed["public_key"] != initial["public_key"]),
    }
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if all(result.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
