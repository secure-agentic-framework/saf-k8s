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
