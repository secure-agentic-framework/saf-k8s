# SAF-K8S-0405-010 API impersonation audit logging and alerting

Run the case by ID on fresh Kind. The API server logs metadata for real
requests from two temporary, scoped ServiceAccounts. Both may delegate
to a fictional read-only user on a public fixture. The detector compares
the original and impersonated identities with a separate approved-pair
list. One finding reaches the in-cluster fixture queue. The approved
pair can continue to read without creating an additional finding.

The native audit events are corroborated within the disposable cluster.
The test retains sanitized observations and leaves deployed collection
coverage, retention, external delivery and response timing to site review.

- [Kubernetes impersonation auditing](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/user-impersonation/#auditing)
- [Kubernetes auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
