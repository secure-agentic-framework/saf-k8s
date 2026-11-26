# SAF-K8S-1001-026 durable audit delivery

Run from the SAF-K8S framework checkout with OpenSSL and the usual Kind prerequisites.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1001-026 --docker-context desktop-linux
```

The Kubernetes v1.36.1 API server delivers native audit webhook batches over
TLS to a fixture receiver. The audit policy selects metadata for ConfigMap
requests in the fixture namespace. The runner matches the API response's
Audit-Id to the actual delivered ResponseComplete event.

Recreating an emptyDir-backed receiver loses the first event. Recreating the
PVC-backed receiver keeps the prior event and uses the same claim and volume
binding. A new, distinct audit event reaches the replacement receiver.
The receiver writes each batch to disk and calls fsync before acknowledging it.

The case creates a temporary CA and named TLS certificate for each run. The
cluster has a case-owned local-path PVC. Production exporters, managed control
planes, protection of audit storage, retention policy, and storage across a
node or other failure domain require separate evidence.

- [Kubernetes v1.36 audit backends](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes v1.36 persistent volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/)

## Adopter verification

1. Inventory each customer-controlled and managed-cluster audit source, effective audit policy, backend/receiver identity, storage topology, and provider responsibility boundary.
2. In an approved staging environment, send an inert API event and match the server-generated Audit-ID to the destination record. Verify secure delivery and what a successful destination acknowledgement guarantees.
3. Verify the stored record survives the failure modes the deployed design claims to cover, including receiver restart and, where required, rescheduling or storage/node failure-domain transition. Use approved staging evidence rather than destructive production experiments.
4. Check retry, buffering, backpressure, recovery and duplicate handling for temporary receiver unavailability, then confirm source coverage and retain the observed record IDs, timestamps, storage settings and failure/recovery results.
5. For managed control planes, retain the provider's authoritative audit-delivery and storage guarantees plus configuration evidence available to the customer. Treat long-term retention and tamper resistance as separate claims.

The AU-4(1) relation is limited to the reviewed audit transfer component. Assess alternate collection and logging on actual primary failures wherever the adopted architecture requires it.

[NIST SP 800-53 Revision 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
