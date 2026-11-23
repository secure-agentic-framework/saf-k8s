# SAF-K8S-0405-021 Emergency activation approval

Run by ID on fresh Kind. The actual admission controller verifies
the authenticated writer of each approval. A separate policy checks
both approvals and exact object scope before admitting the recovery
RoleBinding. Real temporary credentials exercise the resulting
ordinary read. The case reuses the credential helper in SAF-K8S-0405-020.

Operational separation between people, MFA and all production
activation paths require site evidence.

- [Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
