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

## Verify an adopting implementation

Map the emergency workflow from identity provider and
approval system through console, API server, collection, alerting, and archive.
In a controlled exercise, correlate a named allowed and denied harmless API
request to authenticated human identity, object, verb, status, and audit ID;
include a deliberate excluded-source comparator to confirm coverage gaps are
detected. Verify loss alerts, access restrictions, retention, independent
review, and post-use withdrawal without placing credential or object payloads
in the evidence record.
