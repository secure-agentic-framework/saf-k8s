# SAF-K8S-0405-018 Protected credential storage and lifecycle

Run by ID on fresh Kind. The test observes an inert Secret comparator
before and after activating Secretbox protection. Exact raw storage
checks use only the case-owned record and retain only booleans.
The API accepts a short-lived fixture credential while denying it
access to its store, then rejects the old bound credential after
replacement. An independent permitted identity remains available.

This uses the credential helper in SAF-K8S-0405-020. Verify actual
key custody, every issuer, certificate and password storage,
backup coverage and protected evidence at deployment.

- [Kubernetes encryption at rest](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
- [Kubernetes service account administration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)

## Verify an adopting implementation

Inventory credential classes and storage paths, API
encryption providers, key owners, backup copies, issuers, and relying parties.
For each protected store, use an approved synthetic comparator to verify
encrypted raw storage and an authorized read; confirm unauthorized reads fail.
Replace a test credential, verify old-credential denial and independent
service continuity, then reconcile key/backup restore evidence and audit
coverage. Treat external passwords, certificates, and cloud identities as
separate provider evidence.
