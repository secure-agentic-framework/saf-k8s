# SAF-K8S-0910-028 unified multi-cluster compliance evidence

Run `python3 lab.py test SAF-K8S-0910-028` from the lab directory.

Two distinct Kubernetes APIs apply different Pod Security Admission labels.
Each receives the same harmless server-side dry-run, and its own Metadata
audit log supplies the actual response event. The collector preserves the
member, control result, captured event and explicit fixture exception in one
immutable report. A resource-scoped independent reviewer verifies the report
and cannot modify it. Missing, unobserved and stale input remain explicit
states. The normalized receipt is stable across independent runs. The raw
receipt retains each run's real audit identifiers.

The case covers one control and one required audit event per member.
Scheduled warehouse ingestion, fleet coverage and operational reviews need
deployment evidence.

- [Kubernetes v1.36 Pod Security Admission](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Kubernetes v1.36 auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)

## Adopter verification

1. Define the report's purpose, authoritative member inventory, owners, report period, included control IDs/types, expected event sources, delivery schedule and responsible reviewer. Reconcile each report's members to the inventory as of the report timestamp. State explicitly which clusters and controls are not covered.
2. For each included member, retain authenticated source identity, control/policy version, observed result, collection timestamp, source event identifier, freshness and exception ID/owner/approval/expiry. Preserve `missing`, `unobserved`, `stale`, failed ingestion and unknown states; never normalize them to `pass`.
3. Demonstrate source-to-report fidelity for an approved representative result and its native audit event. Compare event IDs, member identity, control result and exception provenance to the source records; retain the query, collector identity, ingestion status and any gap/late-arrival reconciliation.
4. Verify the report store's writer identity, independent reviewer access, unauthorized reader denial, immutability/tamper evidence, retention and recovery using the organization's approved nonproduction or audit method. Preserve access and change history for report policy and schema.
5. Route material failed, missing, stale and exception-expiry states to named owners. Record disposition, remediation, approval and closure evidence. Show the review frequency and that output reaches those accountable roles.
6. To claim federation-wide or continuous CA-7 coverage, reconcile all in-scope members and controls and show scheduled collection, control assessment/monitoring frequencies, freshness thresholds, analysis, response actions and reporting. The three-check fixture is only a portable one-control/two-member example; it is not that fleet-wide assessment.
