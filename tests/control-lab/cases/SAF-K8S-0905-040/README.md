# Verify registry audit delivery and authoritative permission changes

    python3 tests/control-lab/lab.py test SAF-K8S-0905-040 --docker-context desktop-linux

The case compares Zot's local audit and access records with authenticated
Fluent Bit forwarding. It covers selected OCI publication, pulls, tag and
deletion actions, a registered public fixture trust key, the receiver's
enrolled credential, and readback after the receiver Pod is replaced.

One additional bounded fixture check causes the TLS and credential-protected
receiver to return HTTP 503 once, before storing a uniquely marked inert Zot
access event. It checks that Fluent Bit resends the identical request body and
that the exact marked source event is committed once. The two outputs use an
explicit finite retry limit of eight with a 1–2 second exponential scheduler
window. This is one transient rejection/recovery observation; it does not prove
long outage buffering, sender restart recovery, or general exactly-once delivery.

A separate case-owned Kubernetes configuration owner modifies the
exact registry ConfigMap. Metadata-only audit records the scoped actor
and the successful change. The observer compares the resource revision,
the deployed configuration and an owned registry read that changes from
allowed to denied after rolling the registry Pod with its persistent data. The
registry access records reach the receiver. The policy-change audit event comes
from the Kubernetes configuration owner’s API path.

For each deployed registry, inventory the authoritative event sources,
effective authorization revisions, adopted administrative and OCI
operations, and protected forwarding. Verify applicable outage and retry
behavior, covered providers, and required retention of both registry and
configuration-owner records.

- [Zot v2.1.23 configuration and reload](https://zotregistry.dev/v2.1.23/admin-guide/admin-configuration/)
- [Kubernetes API audit](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
