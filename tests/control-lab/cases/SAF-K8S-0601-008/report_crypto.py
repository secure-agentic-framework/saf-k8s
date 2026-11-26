"""Call the pinned Linux runtime's OpenSSL library for Ed25519 verification."""
import base64
import ctypes


ED25519_DER_PREFIX = bytes.fromhex('302a300506032b6570032100')


def openssl():
    library = ctypes.CDLL('libcrypto.so.3')
    pointer = ctypes.c_void_p
    text = ctypes.c_char_p
    size = ctypes.c_size_t
    library.EVP_PKEY_new_raw_public_key_ex.argtypes = [pointer, text, text, text, size]
    library.EVP_PKEY_new_raw_public_key_ex.restype = pointer
    library.EVP_PKEY_free.argtypes = [pointer]
    library.EVP_PKEY_free.restype = None
    library.EVP_MD_CTX_new.argtypes = []
    library.EVP_MD_CTX_new.restype = pointer
    library.EVP_MD_CTX_free.argtypes = [pointer]
    library.EVP_MD_CTX_free.restype = None
    library.EVP_DigestVerifyInit.argtypes = [pointer, pointer, pointer, pointer, pointer]
    library.EVP_DigestVerifyInit.restype = ctypes.c_int
    library.EVP_DigestVerify.argtypes = [pointer, text, size, text, size]
    library.EVP_DigestVerify.restype = ctypes.c_int
    return library


def verify(public_pem, signature, payload):
    pem_lines = public_pem.splitlines()
    if len(pem_lines) != 3 or pem_lines[0] != '-----BEGIN PUBLIC KEY-----' or pem_lines[2] != '-----END PUBLIC KEY-----':
        return False
    encoded = base64.b64decode(pem_lines[1], validate=True)
    if len(encoded) != len(ED25519_DER_PREFIX) + 32 or not encoded.startswith(ED25519_DER_PREFIX) or len(signature) != 64:
        return False
    key_bytes = encoded[len(ED25519_DER_PREFIX):]
    library = openssl()
    key = library.EVP_PKEY_new_raw_public_key_ex(None, b'ED25519', None, key_bytes, len(key_bytes))
    context = library.EVP_MD_CTX_new()
    try:
        return bool(key and context
                    and library.EVP_DigestVerifyInit(context, None, None, None, key) == 1
                    and library.EVP_DigestVerify(context, signature, len(signature), payload, len(payload)) == 1)
    finally:
        library.EVP_MD_CTX_free(context)
        library.EVP_PKEY_free(key)
