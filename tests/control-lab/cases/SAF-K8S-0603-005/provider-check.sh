set -eu
cd /tmp
mkdir -p saf-provider-probe
cd saf-provider-probe
umask 077

OPENSSL_CONF=/dev/null openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 \
    -out baseline-key.pem 2>/dev/null
test -s baseline-key.pem
printf '%s\n' 'BASELINE_SMALL_KEY_GENERATED'

export OPENSSL_CONF=/opt/saf-openssl/etc/provider.cnf
openssl version -v
openssl list -providers -verbose
OPENSSL_CONF=/dev/null openssl fipsinstall -verify \
    -module /opt/saf-openssl/lib/ossl-modules/fips.so \
    -in /opt/saf-openssl/etc/fipsmodule.cnf -section_name fips_sect
printf '%s\n' 'MODULE_CONFIGURATION_VERIFIED'
if openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 \
    -out weak-key.pem -propquery fips=yes >weak-output.txt 2>&1; then
    printf '%s\n' 'OUT_OF_POLICY_KEY_GENERATED'
    exit 20
fi
grep -Ei 'key size|invalid modulus|invalid.*size|invalid.*strength' weak-output.txt
test ! -s weak-key.pem
printf '%s\n' 'OUT_OF_POLICY_KEY_REJECTED'

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out approved-key.pem \
    -propquery fips=yes 2>/dev/null
openssl pkey -in approved-key.pem -pubout -out approved-public.pem -propquery fips=yes
printf '%s\n' 'Synthetic artifact for SAF-K8S-0603-005' > artifact.txt
openssl dgst -sha256 -sign approved-key.pem -out artifact.sig -propquery fips=yes artifact.txt
openssl dgst -sha256 -verify approved-public.pem -signature artifact.sig -propquery fips=yes artifact.txt
printf '%s\n' 'APPROVED_SIGN_AND_VERIFY'
printf '%s\n' 'Different synthetic artifact' > other.txt
if openssl dgst -sha256 -verify approved-public.pem -signature artifact.sig \
    -propquery fips=yes other.txt >verify-output.txt 2>&1; then
    printf '%s\n' 'OTHER_ARTIFACT_ACCEPTED'
    exit 21
fi
grep -i 'Verification failure' verify-output.txt
printf '%s\n' 'OTHER_ARTIFACT_REJECTED'
