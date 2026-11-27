# SAF-K8S-0602-007 — Emergency review record integrity

Run `python3 lab.py test SAF-K8S-0602-007` from the control lab.

The fixture stores an inert request in a dedicated ConfigMap. RBAC limits
approval to two separate ServiceAccounts. Native admission associates each
approval field with its reviewer and freezes the request ID, target digest,
and recorded expiry. The requester can read the approvals and cannot
approve the request or gain Pod-create permissions.

The fixture exercises custody of a synthetic approval record. The recorded
deadline is immutable. Actual trusted-time enforcement, remote audit delivery
and retention, and the deployed emergency process need separate evidence. The
ConfigMap has no consumer that admits images or launches Pods.

## Fixed-input expiry reference

One grouped result reads back the fixed, inert,
two-reviewer approval record that the native case persisted, and sends that
record plus its exact request to a separate local Python consumer process. The
process receives fixed UTC test instants over stdin: one
second before the recorded deadline, exactly at the deadline, and a
request-ID mismatch before the deadline. The harness independently reads the
record again through the Kubernetes API, checks its fingerprint is unchanged,
and compares the consumer's small verdicts. Expected decisions are current exact request: allow; at expiry:
deny; different request: deny. This adds no credentials, bypass, image, or
workload activity.

This is application-level reference logic only. Kubernetes v1.36 Validating
Admission Policy expressions receive the request/object/parameter context, but
no trusted current-time input; the current native fixture therefore does not
enforce expiry. The supplemental timestamp is test input, not the host clock or
a trusted-time source. It does not prove a deployed expiry controller, an
actual image-signature exception, or deployed audit/revocation integration.
Adopters must separately show their trusted time source, the enforcement
component that consumes it, deny behavior at and after expiry, and correlated
audit delivery evidence.

[Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)

## Monotonic revocation check

The case preserves the original eight assertions, adds one grouped fixed-input
expiry reference check, and adds a second case-owned ConfigMap bound to the exact approved
request ID, digest, expiry, and approval fingerprint. Reusing the existing
reviewer ServiceAccounts, RBAC style, native ValidatingAdmissionPolicy, and
fixed-time consumer, it checks that the designated security reviewer can
transition `active` to `revoked`, the operations reviewer cannot make that
transition despite scoped patch permission, and the revoked state cannot be
restored. Independent GETs verify the approval record remains unchanged and
the consumer denies the same request after revocation.

This remains inert metadata and reference consumer behavior. The time instant
is fixed test input, not a trusted clock. The VAP uses `Deny` only; the case
does not link the record to image admission, and it does not launch Pods or
workloads. A final bounded check configures the disposable Kind API server's
blocking audit log for only ConfigMap patch/update requests in `saf-test`.
It correlates the exact synthetic cross-vote denial and both separate approved
votes by audit ID, impersonated ServiceAccount, object name, request fields,
and response status. The local log is projected to an allowlist of these
fixture fields; it is not forwarded and proves no remote delivery, retention,
human approval, or deployed enforcement integration.

The published 11-check baseline uses one Kind control-plane node and adds no
workload Pods. Its raw supplemental artifacts are
`revocation-lifecycle.raw.json` and `approval-audit-correlation.raw.json`.

## Live local expiry observation

The candidate adds one grouped check and one small Job Pod, for 12 checks total.
It creates one separate, harmless approval record with a
45-second future expiry. It first brings up a bounded, non-root Job that waits
for that exact record. Two existing synthetic reviewer identities approve
only its two vote fields; a scoped VAP freezes the request ID, digest, and
expiry. The Job reads only the named record through its narrowly scoped
ServiceAccount, runs the same `expiry_consumer.decide` logic with its actual
UTC clock, and observes the same approved request allowed before expiry and
denied after expiry. A bounded 200 ms sleep is used only to cross the real
expiry boundary; the Job has a 120-second active deadline and a 45-second
record window. It never edits the approval record after the two votes.

The harness also brackets record creation and Job completion with its own UTC
observations and compares the API server's `metadata.creationTimestamp` with
that interval. Dynamic timestamps and record UIDs stay in
`live-expiry-observations.raw.json` and bounded command logs; normalized check
observations are fixed booleans. The original approval record, including its
expiry and approvals, is read back unchanged.

This exercises a real local UTC expiry decision in one disposable Kind Job.
The Job, API server, and harness share the local host clock lineage, so these
observations do not establish trusted time, NTP correctness, drift monitoring,
or production expiry enforcement. The Job does not connect the inert record
to image admission, an exception mechanism, or workload execution. Adoption
still requires evidence for the actual trusted clock chain, deployed consumer,
human authority, and audit delivery/retention.

[Kubernetes v1.36 Auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
