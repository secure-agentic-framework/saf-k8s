# SAF-K8S-0910-017 — Centralized orchestration audit logging

Run `python3 tests/control-lab/lab.py test SAF-K8S-0910-017 --docker-context desktop-linux` from the framework checkout.

Two disposable source clusters each use a scoped workload identity to create an
inert Deployment and update a placement record. Their API servers emit exact
Metadata audit events. The fixture driver selects the bounded source fields.
Case-owned source Pods then deliver those records to a separate Kubernetes hub
over verified mutual TLS. The hub binds source-certificate identity to the
observed source cluster and refuses an unapproved identity issued by the same
test CA.

A separate authenticated observer reports which enrolled sources are missing.
After one verified batch arrives, it reports the held source. The second
verified delivery clears the gap. The receiver uses its own projected identity
to preserve the exact events in an immutable central record. The allowed
reader retrieves it after both source clusters are deleted. A separate
unauthorized reader receives a denial.

The fixture demonstrates a bounded delivery gap, protected delivery, and
retention across source removal. Adoption should verify actual exporters,
permitted event coverage and source trust, native timestamp correlation
tolerance, retry and delivery alerts, independently durable storage and
authorized analyst review. Use the organization's approved retention and
restoration procedures to verify availability across actual backend failures.

- [Kubernetes v1.36 audit policy](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/#audit-policy)
- [NIST OSCAL versioned controls](https://github.com/usnistgov/oscal-content/releases/tag/v1.5.0)
