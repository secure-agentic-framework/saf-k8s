# SAF-K8S-0405-020 Scoped recovery exercise

Run by ID on fresh Kind. The real API first accepts a temporary
routine credential, then rejects it when its bound Secret is deleted.
The separately authorized recovery context can still perform one
named read. Reissuing the routine context restores the read while
the old credential remains invalid and temporary recovery access is
withdrawn. Evidence contains no credential material.

This case exercises a defined local credential-unavailability
scenario. Site verification must exercise the real normal dependency,
approved recovery factors, privileged authorization, operator workflow
and disengagement.

- [Kubernetes service account token administration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
- [Kubernetes authentication](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/)
