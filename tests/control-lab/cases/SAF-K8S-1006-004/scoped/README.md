# SAF-K8S-1006-004

The two synthetic namespaces contain workload RoleBindings and NetworkPolicies, and have
Pod Security Admission labels. Each namespace has a dedicated read-only collector identity.
The Job reads its namespace by exact name and receives a Forbidden result for an exact
read of the other namespace. Effective authorization checks cover permitted reads and
denied writes or Secret reads. No credentials are included in the receipts.

The lab independently compares source UIDs and resource versions from the live API with
each capture and verifies the collector Pod identity and content hash. It records a missing
snapshot, watches the original become stale and verifies a fresh replacement. The other
namespace provides a separate, scoped sample. The receipts preserve timestamps and the
projected source objects.

The capture demonstrates API state and evidence freshness. Deployed snapshot schedules,
policy dataplane effectiveness, benchmark ingestion, framework coverage, retention,
dashboards and GRC integration require separate evidence.

- [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Pod Security Admission](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-admission/)


## Canonical crosswalk counterfactual

The additive fixture freezes the 16 structured `SAF-K8S-1006-004` rows from
`saf_k8s_crosswalks.yaml`, the repository revision, source-file and control-page
SHA-256 values, plus each generated framework reverse-page path and SHA-256. The
case verifies fixture fingerprints and generated-link relationships, then checks
that removing one row and changing the crosswalk-source fingerprint produce
visible attention states. All 16 mappings remain `conditional`; applicability is
unresolved and the projection must remain `attention`.

This is a bounded static fixture counterfactual. It does not evaluate a real
organization's applicability, regulatory scope, retention, authorization,
framework coverage, dashboard integration, or compliance. The original synthetic
projector checks remain unchanged.
