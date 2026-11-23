# SAF-K8S-0505-004 audit detection

The test creates a dedicated Kind cluster and enables a blocking
Metadata audit policy for three harmless exact-name ConfigMap requests.
A restrictive Role admits two reads and rejects one. The audit policy
keeps the ordinary and rejected records and explicitly omits the other
ordinary request. A local rule correlates the 403 with the expected
identity and audit ID while the ordinary record produces no alert.

The recorded network address is context for this fixture. Verify trusted
origin attribution, audit forwarding, alert delivery, and supported
provider configuration in the deployment.

[Kubernetes auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
· [Audit Event reference](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/#Event)
