# SAF-K8S-0910-033 cross-cluster anomaly investigation

Run `python3 lab.py test SAF-K8S-0910-033` from the lab directory.

The same harmless source Pod sends four synthetic telemetry records to an
owned mTLS receiver, which creates a threshold alert. An independent
observer retrieves the received records. The scoped investigator first
sees an incomplete attribution. The source Pod then uses its own bounded
Kubernetes API rights to record the observed data digest. The API server
emits native Metadata audit evidence, including the originating Pod UID.
An exact match permits a bounded fixture disposition. Missing and
inconsistent evidence stay unknown, and RBAC refuses unrelated readers
and investigator writes.

The case covers one known synthetic communication and one attribute
correlation. Production playbooks, evidence retention and unobserved
or ambiguous real incidents require further evidence.

- [Kubernetes v1.36 auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes v1.36 bound service account identities](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
