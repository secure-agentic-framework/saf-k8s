"""In-memory Ed25519 key from the reviewed 0905-005 OpenSSL 3 helper."""
import base64
import ctypes

from signature_crypto_base import ED25519_DER_PREFIX, openssl, verify


class EphemeralSigner:
    """Generate one private key in memory and sign bounded canonical receipts."""
    def __init__(self):
        self.lib = openssl()
        ptr, cstr, size = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t
        self.lib.EVP_PKEY_CTX_new_from_name.argtypes = [ptr, cstr, cstr]
        self.lib.EVP_PKEY_CTX_new_from_name.restype = ptr
        self.lib.EVP_PKEY_CTX_free.argtypes = [ptr]
        self.lib.EVP_PKEY_keygen_init.argtypes = [ptr]
        self.lib.EVP_PKEY_keygen.restype = ctypes.c_int
        self.lib.EVP_PKEY_keygen.argtypes = [ptr, ctypes.POINTER(ptr)]
        self.lib.EVP_PKEY_get_raw_public_key.argtypes = [ptr, ptr, ctypes.POINTER(size)]
        self.lib.EVP_PKEY_get_raw_public_key.restype = ctypes.c_int
        self.lib.EVP_PKEY_free.argtypes = [ptr]
        self.context = self.lib.EVP_PKEY_CTX_new_from_name(None, b"ED25519", None)
        self.key = ptr()
        if not self.context or self.lib.EVP_PKEY_keygen_init(self.context) != 1:
            raise RuntimeError("fixture signing context unavailable")
        if self.lib.EVP_PKEY_keygen(self.context, ctypes.byref(self.key)) != 1 or not self.key:
            raise RuntimeError("fixture key generation failed")
        public_size = size(0)
        if self.lib.EVP_PKEY_get_raw_public_key(self.key, None, ctypes.byref(public_size)) != 1:
            raise RuntimeError("fixture public key unavailable")
        raw = ctypes.create_string_buffer(public_size.value)
        if self.lib.EVP_PKEY_get_raw_public_key(
                self.key, ctypes.cast(raw, ptr), ctypes.byref(public_size)) != 1:
            raise RuntimeError("fixture public key export failed")
        encoded = base64.b64encode(ED25519_DER_PREFIX + raw.raw[:public_size.value]).decode("ascii")
        self.public_pem = f"-----BEGIN PUBLIC KEY-----\n{encoded}\n-----END PUBLIC KEY-----\n"

    def sign(self, payload):
        ptr, size = ctypes.c_void_p, ctypes.c_size_t
        self.lib.EVP_MD_CTX_new.argtypes = []
        self.lib.EVP_MD_CTX_new.restype = ptr
        self.lib.EVP_MD_CTX_free.argtypes = [ptr]
        self.lib.EVP_DigestSignInit.argtypes = [ptr, ctypes.POINTER(ptr), ptr, ptr, ptr]
        self.lib.EVP_DigestSignInit.restype = ctypes.c_int
        self.lib.EVP_DigestSign.argtypes = [ptr, ptr, ctypes.POINTER(size), ptr, size]
        self.lib.EVP_DigestSign.restype = ctypes.c_int
        context = self.lib.EVP_MD_CTX_new()
        data = ctypes.create_string_buffer(payload)
        try:
            if not context or self.lib.EVP_DigestSignInit(context, None, None, None, self.key) != 1:
                raise RuntimeError("fixture signing initialization failed")
            length = size(0)
            if self.lib.EVP_DigestSign(context, None, ctypes.byref(length),
                                       ctypes.cast(data, ptr), len(payload)) != 1:
                raise RuntimeError("fixture signature sizing failed")
            output = ctypes.create_string_buffer(length.value)
            if self.lib.EVP_DigestSign(context, ctypes.cast(output, ptr), ctypes.byref(length),
                                       ctypes.cast(data, ptr), len(payload)) != 1:
                raise RuntimeError("fixture signature failed")
            return output.raw[:length.value]
        finally:
            if context:
                self.lib.EVP_MD_CTX_free(context)

    def close(self):
        if self.key:
            self.lib.EVP_PKEY_free(self.key)
            self.key = ctypes.c_void_p()
        if self.context:
            self.lib.EVP_PKEY_CTX_free(self.context)
            self.context = ctypes.c_void_p()
