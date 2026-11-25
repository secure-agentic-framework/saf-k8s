# SAF-K8S-0102-024 Independent access audit boundaries

A scoped Kind audit policy certifies actual metadata-only API reads of a single public marker. A separate repository socket in a Pod permits and denies reads based on Linux peer UID and emits its own structured events. The test verifies the two event streams without generating or inspecting any real Kubernetes backup or credential. Deployed repository and media audit, protected storage, retention and delivery require separate evidence.

## Adopter verification

Record an event and evidence row for each applicable boundary. Map ordinary,
automation and emergency identities to appropriate observed actions. Identify
provider-operated paths and use supported assurances for inaccessible events.

| Boundary | Required evidence |
| --- | --- |
| Kubernetes API | Effective audit policy and backend, actor, target, verb, result and observed time for an allowed and refused operation |
| Storage service or snapshot repository | Native data-plane logging, object/version, operation and result, actual delivery and a retrieved record |
| Host file or managed media | Host or custodian identity, read/copy/restore decisions and the applicable audit or custody record |
| Offline custody | Authorized checkout, requester and custodian, media identifier, timestamps, outcome and review |
| Central collection | Protected ingestion, access and integrity controls, retention period, successful retrieval and pipeline failure signal |

Compare each controlled action with the resulting retained record. Record
unsupported event categories and compensating evidence and keep sensitive
payload and credentials outside the assessment. The independent
[durable audit ingestion case](../SAF-K8S-1001-026/README.md) exercises TLS
webhook delivery, persistence after replacement and post-replacement ingestion.
