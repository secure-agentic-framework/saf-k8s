"""Call the pinned Linux runtime's OpenSSL 3 library for Ed25519 operations."""
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


def generate_and_sign(payloads):
    """Generate one ephemeral Ed25519 key and sign payloads without exporting it."""
    library = openssl()
    pointer = ctypes.c_void_p
    text = ctypes.c_char_p
    size = ctypes.c_size_t

    library.EVP_PKEY_CTX_new_from_name.argtypes = [pointer, text, text]
    library.EVP_PKEY_CTX_new_from_name.restype = pointer
    library.EVP_PKEY_CTX_free.argtypes = [pointer]
    library.EVP_PKEY_CTX_free.restype = None
    library.EVP_PKEY_keygen_init.argtypes = [pointer]
    library.EVP_PKEY_keygen_init.restype = ctypes.c_int
    library.EVP_PKEY_keygen.argtypes = [pointer, ctypes.POINTER(pointer)]
    library.EVP_PKEY_keygen.restype = ctypes.c_int
    library.EVP_PKEY_get_raw_public_key.argtypes = [pointer, pointer, ctypes.POINTER(size)]
    library.EVP_PKEY_get_raw_public_key.restype = ctypes.c_int
    library.EVP_DigestSignInit.argtypes = [pointer, ctypes.POINTER(pointer), pointer, pointer, pointer]
    library.EVP_DigestSignInit.restype = ctypes.c_int
    library.EVP_DigestSign.argtypes = [pointer, pointer, ctypes.POINTER(size), pointer, size]
    library.EVP_DigestSign.restype = ctypes.c_int

    key_context = library.EVP_PKEY_CTX_new_from_name(None, b"ED25519", None)
    if not key_context:
        raise RuntimeError("OpenSSL Ed25519 key context unavailable")
    private_key = pointer()
    try:
        if (library.EVP_PKEY_keygen_init(key_context) != 1 or
                library.EVP_PKEY_keygen(key_context, ctypes.byref(private_key)) != 1 or
                not private_key):
            raise RuntimeError("OpenSSL Ed25519 key generation failed")

        public_length = size(0)
        if library.EVP_PKEY_get_raw_public_key(private_key, None, ctypes.byref(public_length)) != 1:
            raise RuntimeError("OpenSSL Ed25519 public key sizing failed")
        public_bytes = ctypes.create_string_buffer(public_length.value)
        if library.EVP_PKEY_get_raw_public_key(
                private_key, ctypes.cast(public_bytes, pointer), ctypes.byref(public_length)) != 1:
            raise RuntimeError("OpenSSL Ed25519 public key export failed")
        der = ED25519_DER_PREFIX + public_bytes.raw[:public_length.value]
        encoded = base64.b64encode(der).decode("ascii")
        public_pem = "-----BEGIN PUBLIC KEY-----\n" + encoded + "\n-----END PUBLIC KEY-----\n"

        signatures = []
        for payload in payloads:
            context = library.EVP_MD_CTX_new()
            if not context:
                raise RuntimeError("OpenSSL Ed25519 signing context unavailable")
            try:
                if library.EVP_DigestSignInit(
                        context, None, None, None, private_key) != 1:
                    raise RuntimeError("OpenSSL Ed25519 signing initialization failed")
                payload_buffer = ctypes.create_string_buffer(payload)
                signature_length = size(0)
                if library.EVP_DigestSign(
                        context, None, ctypes.byref(signature_length),
                        ctypes.cast(payload_buffer, pointer), len(payload)) != 1:
                    raise RuntimeError("OpenSSL Ed25519 signature sizing failed")
                signature_buffer = ctypes.create_string_buffer(signature_length.value)
                if library.EVP_DigestSign(
                        context, ctypes.cast(signature_buffer, pointer),
                        ctypes.byref(signature_length), ctypes.cast(payload_buffer, pointer),
                        len(payload)) != 1:
                    raise RuntimeError("OpenSSL Ed25519 signing failed")
                signatures.append(signature_buffer.raw[:signature_length.value])
            finally:
                library.EVP_MD_CTX_free(context)
        return public_pem, signatures
    finally:
        if private_key:
            library.EVP_PKEY_free(private_key)
        library.EVP_PKEY_CTX_free(key_context)
