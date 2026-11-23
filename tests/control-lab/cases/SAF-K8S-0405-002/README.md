# SAF-K8S-0405-002 Defensive RBAC audit coverage

Run by ID on fresh Kind. A fixture administrator creates two
non-sensitive readers and a workload's annotation change is denied.
Native audit records feed an owned review queue. The fixture preserves
separate classifications for unexpected approved-authority activity
and a denied workload request, with no request or response objects.

The case evaluates the selected RBAC path only. Production event
selection, token misuse indicators, runtime sensors, alert delivery
and response objectives require separate evidence.

- [Kubernetes auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
