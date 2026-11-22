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
