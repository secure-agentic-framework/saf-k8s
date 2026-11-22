# SAF-K8S-0904-008 — Feature freshness and integrity

Five case-owned Kubernetes Jobs use fixed synthetic inputs. Without the gate
the consumer reads stale data. The full policy uses an init container to
compare age with an independent 300-second limit and compare canonical data
with a pinned SHA-256 digest. The live Job and Pod state confirms that the
stale and mismatched cases stop at the init container. The exact age
boundary is allowed. A freshness-only control accepts the different
fixed content and demonstrates why the integrity check matters.

The retained raw report includes the Job and container states, gate
receipts, and downstream markers. Feature-store provenance, adversarial
anomaly detection, production alerting, and rollout performance require
separate evidence.
