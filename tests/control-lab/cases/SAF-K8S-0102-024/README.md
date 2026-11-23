# SAF-K8S-0102-024 Independent access audit boundaries

A scoped Kind audit policy certifies actual metadata-only API reads of a single public marker. A separate repository socket in a Pod permits and denies reads based on Linux peer UID and emits its own structured events. The test verifies the two event streams without generating or inspecting any real Kubernetes backup or credential. Deployed repository and media audit, protected storage, retention and delivery require separate evidence.
