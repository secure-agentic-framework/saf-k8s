# SAF-K8S-0403-004 Credential lifecycle

Run `python3 lab.py test SAF-K8S-0403-004` against the revision from the verified
result. Kubernetes delivers a replacement to a running consumer while a
disposable Redis ACL remains the actual verifier. The test demonstrates the
initial mismatch, enables a controlled overlap, and removes the old credential
from the authority. Fresh backend connections then reject the retired
credential while the consumer continues using the least-privilege replacement.

The private values and their hashes stay out of output. The case checks
backend revocation on new connections. Issuer-managed TTLs, already
authenticated sessions and provider- or certificate-specific rotation
remain separate obligations.

- [Redis ACL rules](https://redis.io/docs/latest/commands/acl-setuser/)
- [Kubernetes Secret delivery](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/secret/)
