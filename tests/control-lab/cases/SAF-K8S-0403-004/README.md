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

## Adopter verification

1. Inventory the exact issuer, verifier, workload principal, rotation
   operator, credential type and effective versions.
2. Rehearse the approved transition in the selected authority. Verify
   authorized operations with the replacement and refusal of new
   authentication using the retired credential.
3. Test the actual behavior of established sessions separately. Record
   their permitted lifecycle, any required termination, and the verified
   result.
4. Record actual expiry enforcement or authority-side revocation for each
   selected token, certificate, lease, or static credential. Include
   provider phases, dependent services and any controlled grace period.
5. Retain timestamps, sanitized decisions, authority audit references,
   exception approval and owner. Exclude credential material.

The local Redis reference demonstrates its selected ACL replacement and
fresh authentication behavior.
