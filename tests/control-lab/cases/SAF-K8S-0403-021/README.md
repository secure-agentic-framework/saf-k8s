# SAF-K8S-0403-021 Credential inventory

Run `python3 lab.py test SAF-K8S-0403-021` against the recorded catalog revision.
The case uses a known projected Kind credential and real Vault accessor
listing and lookup. The collector persists selected issuer, binding and
lifetime metadata, distinguishes unavailable sources, and observes an
actual short-lived token disappear from the provider's active inventory.

Secret values, bearer tokens and accessors are excluded from evidence.
Only registered source capabilities are claimed. Cluster-wide issuance
visibility, abandoned sources, other credential classes and production
freshness objectives require separate verification.

- [Vault token API](https://developer.hashicorp.com/vault/api-docs/auth/token)
- [Kubernetes service account administration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)

## Freshness decisions

A fixed-clock comparison checks the freshness boundary and distinguishes
stale, denied, unavailable, partial and unsupported sources. A second
comparison takes the selected scoped Vault fixture rows, maps them to
non-secret issuer and workload class metadata, and evaluates controlled
timestamps on both sides of the freshness boundary. The receipt retains
counts and outcome predicates.

For adoption, define the issuer inventory and required credential classes.
Record scoped source authorities, pagination or completeness indicators,
collection cadence and time. Verify decisions against the approved
freshness objective and include denied or incomplete sources in reports.
Validate owner associations and reconcile expiry and revocation at each
actual authority. Preserve sanitized findings and audit references.
