# SAF-K8S-0402-002 — Inactive ServiceAccounts and stale credentials

```sh
python3 lab.py test SAF-K8S-0402-002 --docker-context desktop-linux
```

The fixture provisions four synthetic ServiceAccounts in fresh Kubernetes
v1.36.1. It correlates normal TLS API requests with real audit records by
request ID, time, principal, route, and status. Metadata audit records the
fixture history from creation. Credential material stays in the disposable
cluster and in process memory during probes.

- Missing history, observed activity, and missing approval yield separate
  outcomes that prevent account retirement. The exact approved inactive
  fixture loses its credential, dedicated role binding, and ServiceAccount.
- A bidirectionally referenced synthetic legacy token authenticates first.
  Adding the documented invalidation marker causes HTTP 401 while the marked
  Secret remains. The fixture deliberately applies the marker to test native
  enforcement independently of the cleaner's period and scheduling.
- Deleting a separate previously working legacy Secret causes HTTP 401.
  An independent unaffected identity retains access throughout.

Successful API probes correlate with Metadata at `ResponseComplete`. In this
cluster, the failed authentication probes correlate at `ResponseStarted`,
without an authenticated principal. The result records the successful joins,
without request bodies, response bodies, credentials, or volatile IDs.

Manually created legacy token Secrets are long-lived. Native automatic cleanup
can mark qualifying unused auto-generated tokens invalid and can later delete
them. Deployed history coverage, inactivity thresholds, cleanup timing, system
exceptions, external IAM or Vault revocation, and retention need separate
evidence.

[Kubernetes v1.36 ServiceAccount administration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/) ·
[Kubernetes v1.36 audit guide](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)

## Adopter verification

Define the in-scope namespaces, identity authorities, inactivity and retirement windows, approved exceptions and owners. Verify that collected audit records cover the complete window before treating absence of observed activity as inactivity. Select an owned identity, keep its scoped authorized comparison, and document the approval. Run the effective disablement or retirement workflow and confirm API refusal and removal of the selected grants. Independently verify revocation at each external service for the credentials it accepts. Record the before/after decision, observed request outcomes and retained audit references without keeping token bytes.

For installations that rely on automatic legacy-token cleanup, confirm Kubernetes release behavior, tracked legacy Secret inventory and the approved configured cadence. The local case observes the effect of the invalidation marker and Secret removal. It uses a bounded history and case approval for the retirement decision.
