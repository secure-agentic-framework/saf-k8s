# SAF-K8S-1001-026 source review

The reviewed source is the original catalog at
`133a8698a45e2b335b51728bf4c62f7bda98d15f`. The control requires a
durable audit destination for Kubernetes environments hosting AI workloads.

Kubernetes v1.36 documents both the log and webhook audit backends and the
scope and stages controlled by audit policy. The fixture uses the webhook
option with a narrow namespace and resource policy and validates the exact
native event against the successful request's Audit-Id. Raw audit IDs are
saved separately from assertions that must match across clusters.
[Kubernetes auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)

A PersistentVolumeClaim binds to backing storage with a lifecycle independent
of the receiving Pod. The test compares the same replacement sequence with
emptyDir and a PVC, records the binding and Pod identity checks, then verifies
fresh webhook delivery. The local storage verifies receiver replacement in one
cluster. Managed exports, production retention and integrity, and storage
survival across failures of a node or provider require deployed evidence.
[Persistent volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/)
