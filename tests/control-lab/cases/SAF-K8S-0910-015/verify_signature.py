"""Small OpenSSL-backed RSA/SHA-256 verifier used by the destination fixture."""
from contextlib import ExitStack
from ctypes import CDLL, c_char_p, c_int, c_size_t, c_void_p

OPENSSL = CDLL("libcrypto.so.3")
_API = (
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
for _name, _result, _args in _API:
    _fn = getattr(OPENSSL, _name)
    _fn.restype, _fn.argtypes = _result, _args


def verify(payload, signature, public_pem):
    if not payload or not signature or not public_pem or len(public_pem) > 16384:
        return False
    with ExitStack() as stack:
        bio = OPENSSL.BIO_new_mem_buf(public_pem, len(public_pem))
        if not bio:
            return False
        stack.callback(OPENSSL.BIO_free, bio)
        key = OPENSSL.PEM_read_bio_PUBKEY(bio, None, None, None)
        if not key:
            return False
        stack.callback(OPENSSL.EVP_PKEY_free, key)
        if OPENSSL.EVP_PKEY_is_a(key, b"RSA") != 1:
            return False
        ctx = OPENSSL.EVP_MD_CTX_new()
        if not ctx:
            return False
        stack.callback(OPENSSL.EVP_MD_CTX_free, ctx)
        if OPENSSL.EVP_DigestVerifyInit_ex(ctx, None, b"SHA256", None, None, key, None) != 1:
            return False
        return OPENSSL.EVP_DigestVerify(ctx, signature, len(signature), payload, len(payload)) == 1
