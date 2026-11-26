"""Canonical synthetic promotion-envelope signature format."""
import base64
import copy
import hashlib
import json


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def signing_payload(evidence):
    unsigned = copy.deepcopy(evidence)
    attestation = unsigned.get("attestation", {})
    attestation.pop("signature", None)
    attestation.pop("signer_key_id", None)
    return canonical(unsigned)


def public_key_id(public_pem):
    lines = public_pem.strip().splitlines()
    if (len(lines) != 3 or lines[0] != "-----BEGIN PUBLIC KEY-----" or
            lines[2] != "-----END PUBLIC KEY-----"):
        raise ValueError("invalid fixture public key encoding")
    der = base64.b64decode(lines[1], validate=True)
    return hashlib.sha256(der).hexdigest()
