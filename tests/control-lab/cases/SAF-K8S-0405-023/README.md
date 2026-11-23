# SAF-K8S-0405-023 Emergency API audit coverage

Run by ID on fresh Kind. The API server applies a scoped metadata
audit policy to real allow and deny requests. Compare the observed
decisions with the native identity, object, verb and audit IDs.
The separate reviewer reads a sanitized record. A request outside
the configured coverage provides a deliberate negative comparator.

The case reuses the temporary caller helpers from SAF-K8S-0405-020.
Production collector coverage, retention, human attribution and
credential retirement have their own verification requirements.

- [Kubernetes auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
