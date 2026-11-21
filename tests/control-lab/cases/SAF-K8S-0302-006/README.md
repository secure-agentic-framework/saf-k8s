# SAF-K8S-0302-006 — No-new-privileges execution enforcement

This reference case uses a namespace-scoped `ValidatingAdmissionPolicy` to
require `allowPrivilegeEscalation: false` on regular and init containers during
Pod admission, and on ephemeral containers during an
`pods/ephemeralcontainers` update. The three negative shapes are safe inert
server dry-runs: no noncompliant Pod is persisted or run. A benign compliant Pod
is run and its regular container reads `/proc/self/status`; the expected value
is `NoNewPrivs: 1`.

The case implementation is executable through the repository lab runner, but
this delivery was reviewed statically only. No cluster was created, so its CEL
evaluation, exact API denial text, subresource dry-run support, Pod readiness,
and runtime observation remain unverified.

## Exceptional approval evidence

This case contains no exception path and does not test exceptional approvals.
If an organization permits an approved workload to set
`allowPrivilegeEscalation: true`, evidence of the approval workflow, approver,
scope, duration, and resulting workload controls must be retained separately
from this case's tested evidence. No approval is implied by this reference
policy.
