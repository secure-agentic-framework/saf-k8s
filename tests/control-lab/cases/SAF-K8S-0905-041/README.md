# SAF-K8S-0905-041 — Alert on registry operations and restrict disposition writes

    python3 lab.py test SAF-K8S-0905-041 --docker-context desktop-linux

A case-owned HTTP monitor receives the same forwarded audit corpus with alerting disabled and enabled. It checks sensitive publish, delete, permission and administrative operations and a marked anomalous pull. Ordinary and out-of-scope events stay quiet. Replay must leave the exact alert set unchanged, and records with incorrect source metadata are rejected.

The test links the anomalous pull alert to a Kubernetes disposition object. A read-only account cannot change it. The scoped analyst can patch that named object, and the test rereads it independently.

Fixture labels represent normalized source metadata and an already-classified anomalous event. Integration with each actual registry and SIEM, detection thresholds, production analyst response, identity governance, source authentication and durable retention require separate evidence.

- [Zot monitoring](https://zotregistry.dev/v2.1.23/articles/monitoring/)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
