# SAF-K8S-0103-013 Controller credential boundaries

The Kubernetes API issues short-lived fixture tokens bound to an owned Pod and explicit audiences. Review the intended audience, denial at another audience, distinct reissue and invalidation after the old Pod is deleted. The runner uses the tokens only in memory against its own API server and retains sanitized outcomes. This checks Kubernetes issuance and binding. Provider exchange, issuer trust, automatic consumer refresh and cloud credential retirement need separate deployed evidence.

## Adopter verification

1. Identify the effective credential source and fallback order from the
   running controller configuration. Record the issuer, permitted subject
   and audience, trust configuration, and resulting provider principal.
2. Use the provider's supported identity flow in an approved test
   environment. Verify permitted issuance and use, and rejection of an
   unauthorized audience or subject where supported.
3. Measure the provider session lifetime and observe the controller
   consuming a refreshed credential during a permitted reconciliation.
   Verify that the expected credential source remains in use.
4. Assess retirement at each boundary. Record when the authenticated
   Kubernetes token becomes invalid and verify the expiration or
   revocation of its separately issued provider session.
5. Record exception ownership, scope, expiry, fallback controls and
   withdrawal. Preserve redacted decisions, timestamps, and audit
   references. Exclude credential bytes from shared evidence.

- [Kubernetes v1.36 ServiceAccounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)
- [Kubernetes v1.36 Service Account Administration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
