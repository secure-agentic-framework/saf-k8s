#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <string.h>

static int signature_indicator(EVP_PKEY_CTX *ctx, int *approved) {
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_FIPS_APPROVED_INDICATOR, approved),
        OSSL_PARAM_END
    };
    return EVP_PKEY_CTX_get_params(ctx, params) == 1;
}

int main(void) {
    static const unsigned char message[] = "synthetic FIPS indicator fixture";
    static const char *config = "/opt/saf-openssl/etc/provider.cnf";
    int result = 1, sign_indicator = -1, verify_indicator = -1;
    size_t signature_len = 0;
    unsigned char *signature = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *base = NULL, *fips = NULL;
    EVP_PKEY_CTX *keygen = NULL, *sign_ctx = NULL, *verify_ctx = NULL;
    EVP_MD_CTX *sign_md = NULL, *verify_md = NULL;
    EVP_PKEY *key = NULL;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL || OSSL_LIB_CTX_load_config(libctx, config) != 1)
        goto done;
    base = OSSL_PROVIDER_load(libctx, "base");
    fips = OSSL_PROVIDER_load(libctx, "fips");
    if (base == NULL || fips == NULL)
        goto done;

    keygen = EVP_PKEY_CTX_new_from_name(libctx, "RSA", "fips=yes");
    if (keygen == NULL || EVP_PKEY_keygen_init(keygen) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(keygen, 2048) <= 0 ||
        EVP_PKEY_keygen(keygen, &key) <= 0)
        goto done;

    sign_md = EVP_MD_CTX_new();
    if (sign_md == NULL || EVP_DigestSignInit_ex(sign_md, &sign_ctx, "SHA256",
            libctx, "fips=yes", key, NULL) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(sign_ctx, RSA_PKCS1_PADDING) <= 0)
        goto done;
    int maximum_signature_len = EVP_PKEY_get_size(key);
    if (maximum_signature_len <= 0)
        goto done;
    signature_len = (size_t)maximum_signature_len;
    signature = OPENSSL_malloc(signature_len);
    if (signature == NULL ||
        EVP_DigestSign(sign_md, signature, &signature_len, message, sizeof(message) - 1) != 1 ||
        !signature_indicator(sign_ctx, &sign_indicator) || sign_indicator != 1)
        goto done;

    verify_md = EVP_MD_CTX_new();
    if (verify_md == NULL || EVP_DigestVerifyInit_ex(verify_md, &verify_ctx, "SHA256",
            libctx, "fips=yes", key, NULL) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(verify_ctx, RSA_PKCS1_PADDING) <= 0 ||
        EVP_DigestVerify(verify_md, signature, signature_len, message, sizeof(message) - 1) != 1 ||
        !signature_indicator(verify_ctx, &verify_indicator) || verify_indicator != 1)
        goto done;

    puts("APPROVED_SIGNATURE_AND_VERIFICATION_INDICATORS");
    result = 0;

done:
    OPENSSL_free(signature);
    EVP_MD_CTX_free(verify_md);
    EVP_MD_CTX_free(sign_md);
    EVP_PKEY_CTX_free(keygen);
    EVP_PKEY_free(key);
    if (fips != NULL) OSSL_PROVIDER_unload(fips);
    if (base != NULL) OSSL_PROVIDER_unload(base);
    OSSL_LIB_CTX_free(libctx);
    return result;
}
