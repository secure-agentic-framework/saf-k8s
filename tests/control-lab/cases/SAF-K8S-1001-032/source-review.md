# SAF-K8S-1001-032 source review

The original control at revision 133a8698a45e2b335b51728bf4c62f7bda98d15f
requires case-specific collection coverage across node, container, managed
provider and accelerator log sources. Kubernetes documents DaemonSets as
one way to put an agent on each eligible node. Custom taints need matching
tolerations, and the controller schedules collectors on the eligible nodes.
[DaemonSets](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/daemonset/)

The live fixture verifies the actual desired and ready collectors before and
after adding one exact toleration. Each collector demonstrates two separate
reads. The node source is one read-only lab marker file. The Kubernetes source
is the actual named workload's stdout, read via the log API by a namespaced
ServiceAccount scoped to the three fixture Pods. Raw observations are retained
alongside both replay results.
[RBAC authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
[Logging architecture](https://v1-36.docs.kubernetes.io/docs/concepts/cluster-administration/logging/)

The taint tests scheduling on a labelled worker. Physical accelerator, driver
and managed-service source capture, and rollout coverage in production require
their own deployed evidence.
