# SAF-K8S-0602-004 — Notation trust policy and signing identity

Run `python3 lab.py test SAF-K8S-0602-004` from the control lab.

The case creates two short-lived test CAs and three distinct OCI images in a
loopback-published Distribution registry attached to the disposable Kind node.
Checksum-pinned Notation 1.3.2 signs each exact manifest digest. Without a
trust policy, even the signed image fails verification. With both roots
trusted and wildcard identity matching, all three validate.

The strict policy uses one named CA store and an exact certificate subject
for the fixture repository. Notation rejects the other subject from the
trusted CA and rejects the approved subject from the other CA. It still
validates the approved signer. After verification, a Kubernetes Deployment
runs the exact approved digest. Signing material and Notation configuration
are temporary and belong to the test.

The case exercises CLI verification. Track deployed PKI and signer
rotation, repository coverage, trust policy distribution, and admission
enforcement in the linked review bead.

[Notary Project trust policy specification](https://github.com/notaryproject/specifications/blob/main/specs/trust-store-trust-policy.md)

## Adopter verification

1. Inventory each deployed Notation registry/client pair, repository scope, named trust store and signer identity. link each root to its approved PKI issuance and provenance record.
2. Verify trust-policy distribution and effective use on each build, promotion, pull and deployment path.
3. Demonstrate an approved signature succeeds while a wrong subject and wrong root fail for the intended repository.
4. Exercise authorized signer/root rotation and expiry with a documented overlap, removal of retired trust, rollback and alert path. record deployment/admission consumers separately.
