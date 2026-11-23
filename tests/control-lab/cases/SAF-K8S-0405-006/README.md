# SAF-K8S-0405-006 Attribute-based artifact authorization

Run by ID on fresh Kind. Projected workload credentials are verified
by Kubernetes TokenReview. The case-owned HTTPS artifact service reads
an immutable attribute registry and applies independent classification,
sensitivity and environment criteria to actual reads. Two intended
workload paths retain access to their approved artifact.

The fixture uses public bytes and temporary identities. Verify production
attribute authority, logs, registry and object-store enforcement and
all supported read paths independently.

- [NIST SP 800-162](https://doi.org/10.6028/NIST.SP.800-162)
- [Kubernetes service account administration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
