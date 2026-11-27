# SAF-K8S-0602-007 — Emergency review record integrity

Run `python3 lab.py test SAF-K8S-0602-007` from the control lab.

The fixture stores an inert request in a dedicated ConfigMap. RBAC limits
approval to two separate ServiceAccounts. Native admission associates each
approval field with its reviewer and freezes the request ID, target digest,
and recorded expiry. The requester can read the approvals and cannot
approve the request or gain Pod-create permissions.

The fixture exercises custody of a synthetic approval record. The recorded
deadline is immutable. Trusted-time enforcement, actual expiry, audit
delivery, revocation, and the deployed emergency process need separate
evidence. The ConfigMap has no consumer that admits images or launches Pods.

## Additive expiry reference

The scratch supplement adds one grouped result. It reads back the fixed, inert,
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
actual image-signature exception, or audit/revocation integration. Adopters
must separately show their trusted time source, the enforcement component that
consumes it, deny behavior at and after expiry, and correlated audit evidence.

[Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)

## Additive monotonic revocation check

The scratch candidate preserves all nine published assertions and adds one
grouped check using a second case-owned ConfigMap bound to the exact approved
request ID, digest, expiry, and approval fingerprint. Reusing the existing
reviewer ServiceAccounts, RBAC style, native ValidatingAdmissionPolicy, and
fixed-time consumer, it checks that the designated security reviewer can
transition `active` to `revoked`, the operations reviewer cannot make that
transition despite scoped patch permission, and the revoked state cannot be
restored. Independent GETs verify the approval record remains unchanged and
the consumer denies the same request after revocation.

This remains inert metadata and reference consumer behavior. The time instant
is fixed test input, not a trusted clock. The VAP uses `Deny` only; the case
does not configure or observe an audit backend, does not link the record to
image admission, and does not launch Pods or workloads. These deployed
workflow, trusted-time, audit-delivery, human-approval, and enforcement
integration claims remain separate.

Expected receipt count: ten total, with the nine published assertions
preserved and one additive revocation lifecycle assertion. Raw supplemental
artifact: `revocation-lifecycle.raw.json`.
