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

## Adopter verification

For each API server or managed control plane, keep a scoped deployment verification plan.

1. Inventory enabled impersonation authorities, groups/users/service accounts, allowed verbs and resources, and expected operator-to-impersonated-principal pairs. Exclude secrets and unrelated workloads from test requests.
2. Confirm the effective audit policy captures the impersonation request and the selected metadata fields at the agreed stage. Verify audit backend delivery, event-loss indicators, access controls, retention and time synchronization.
3. Use an approved test identity to read a harmless owned object through one expected impersonation pair, then a second authorized but unapproved synthetic pair. Verify the audit records identify both the authenticated caller and impersonated identity and include the operation/outcome, without recording object payloads.
4. Confirm only the unapproved pair reaches the named review/SIEM queue, correlate it to the original audit event, and document delivery time and assigned responder. Repeat the approved pair to confirm it remains visible without creating a false positive.
5. Retain sanitized query identifiers, matched field names, policy/configuration revision, event timestamps, delivery/acknowledgement and reviewer disposition. Record any gaps in managed audit services and covered paths.

The guide complements the three-check local case: the case proves native audit production and local policy routing; the adopter exercise proves that the organization's actual API paths, protected retention and response target are wired.
