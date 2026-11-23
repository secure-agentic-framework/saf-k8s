# SAF-K8S-0403-022 Orphaned workload credential reconciliation

Run `python3 lab.py test SAF-K8S-0403-022` with the verified catalog revision.
The case joins real Vault tokens to immutable UIDs from completed and failed
Kind Jobs, preserves terminal evidence before deleting a Job, and creates a
new Job with the same name. It verifies that a denied provider operation
leaves the earlier credential valid and that authorized revocation makes
only the two terminal credentials unusable. It also verifies the separate
Pod-bound Kubernetes token lifecycle.

Private fixture values remain out of retained output. Other issuers,
backends and production response windows need environment evidence.

- [Vault token API](https://developer.hashicorp.com/vault/api-docs/auth/token)
- [Kubernetes service account administration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
