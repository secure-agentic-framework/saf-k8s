# SAF-K8S-0402-023 Workload token inventory and exceptions

Run `python3 lab.py test SAF-K8S-0402-023` with the recorded catalog revision.
The case uses metadata from two disposable Secret fixtures to distinguish
a bidirectionally linked legacy-shaped item from a manual unlinked item.
It observes a separate projected-token declaration, checks governance data
on exact fixture identities, identifies a due review, and verifies that
retiring the first Secret removes that inventory entry.

Only metadata is printed. This checks the classification and retirement
workflow on Kind. Actual compatibility validity windows, issued projected
token lifetimes, provider exchanges, and fleet governance require separate
evidence.

- [Kubernetes service account administration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
