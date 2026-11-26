"""Verify fixture lineage against the pinned runtime's OpenSSL library."""
from contextlib import ExitStack
from ctypes import CDLL, c_char_p, c_int, c_size_t, c_void_p
from hashlib import sha256
import json
from pathlib import Path

OPENSSL = CDLL("libcrypto.so.3")
SIGNATURES = (
    ("BIO_new_mem_buf", c_void_p, (c_char_p, c_int)),
    ("BIO_free", c_int, (c_void_p,)),
    ("PEM_read_bio_PUBKEY", c_void_p, (c_void_p, c_void_p, c_void_p, c_void_p)),
    ("EVP_PKEY_free", None, (c_void_p,)),
    ("EVP_PKEY_is_a", c_int, (c_void_p, c_char_p)),
    ("EVP_MD_CTX_new", c_void_p, ()),
    ("EVP_MD_CTX_free", None, (c_void_p,)),
    ("EVP_DigestVerifyInit_ex", c_int, (c_void_p, c_void_p, c_char_p, c_void_p,
                                       c_char_p, c_void_p, c_void_p)),
    ("EVP_DigestVerify", c_int, (c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)),
)
for name, result, arguments in SIGNATURES:
    function = getattr(OPENSSL, name)
    function.restype = result
    function.argtypes = arguments


def verify(payload, signature, public_pem):
    if not payload or not signature or not public_pem or len(public_pem) > 16384:
        return False
    with ExitStack() as released:
        memory = OPENSSL.BIO_new_mem_buf(public_pem, len(public_pem))
        if not memory:
            return False
        released.callback(OPENSSL.BIO_free, memory)
        public_key = OPENSSL.PEM_read_bio_PUBKEY(memory, None, None, None)
        if not public_key:
            return False
        released.callback(OPENSSL.EVP_PKEY_free, public_key)
        if OPENSSL.EVP_PKEY_is_a(public_key, b"RSA") != 1:
            return False
        context = OPENSSL.EVP_MD_CTX_new()
        if not context:
            return False
        released.callback(OPENSSL.EVP_MD_CTX_free, context)
        if OPENSSL.EVP_DigestVerifyInit_ex(context, None, b"SHA256", None, None, public_key, None) != 1:
            return False
        return OPENSSL.EVP_DigestVerify(context, signature, len(signature), payload, len(payload)) == 1


def trusted_public_key(signer_identity, trust_dir="/trust"):
    """Resolve a signer only from separately mounted peer trust policy."""
    root = Path(trust_dir)
    policy_bytes = (root / "trusted-signers.json").read_bytes()
    if len(policy_bytes) > 65536:
        return None, "trust-policy-too-large"
    policy = json.loads(policy_bytes)
    signer = policy.get("signers", {}).get(signer_identity)
    if not isinstance(signer, dict):
        return None, "signer-unapproved"
    if signer.get("state") == "withdrawn":
        return None, "signer-withdrawn"
    if signer.get("state") != "active":
        return None, "trust-policy-invalid"
    public_pem = (root / signer.get("public_key_file", "approved-public.pem")).read_bytes()
    if len(public_pem) > 16384:
        return None, "trusted-key-too-large"
    if sha256(public_pem).hexdigest() != signer.get("public_key_sha256"):
        return None, "trusted-key-fingerprint-mismatch"
    return public_pem, "allowed"
