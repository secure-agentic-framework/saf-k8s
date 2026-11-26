# Verify provider selection and exact cryptographic operations

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0603-005 --docker-context desktop-linux
```

The disposable Kind example builds OpenSSL 3.5.9 and verifies selected provider configuration and an exact signing and verification operation. It compares the variant that permits a smaller key with the selected provider policy that refuses it. An independent check refuses changed artifact bytes. The receipt covers the local build and operations tested.

For adoption, identify the requirement governing each actual signing and verification boundary. Record the module certificate and status, exact module build, loaded version, module integrity evidence, applicable operating environment and versioned security policy. Verify installation and effective mode according to that policy. Observe the actual signing and verification service, including approved service indicators where applicable, and compare an approved request with an out-of-policy one. Evaluate HSM, managed operations and key custody within their actual validated boundaries. Record the certificate match and the independently observed service decision. The fixture's version alone leaves the operating environment and deployed service evidence open.

[CMVP certificate 5586](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5586) · [Module security policy](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5586.pdf)
