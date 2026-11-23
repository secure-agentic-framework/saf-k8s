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
