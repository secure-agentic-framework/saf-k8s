# SAF-K8S-0603-005 — OpenSSL provider configuration

Run `python3 lab.py test SAF-K8S-0603-005` from the control lab. The first run
compiles a checksum-pinned OpenSSL release in Docker. Kind loads the case-owned
image and the script compares default and FIPS provider selection.

The case verifies the module configuration and exercises the defined RSA-2048
and SHA-256 signing path with a synthetic artifact. It challenges the exact
signature with a changed artifact and compares an out-of-policy RSA key
request with the default-provider result.

CMVP certificate #5586 applies to the named OpenSSL FIPS Provider under the
conditions in its security policy. The test measures the fixture configuration.
Use deployed module provenance, applicable operational environment,
vendor certificate, custody, and signing and verification mode evidence for
the applicable requirements.
