# SAF-K8S-0904-011 — Pipeline stage isolation

The case creates isolated stage namespaces and distinct tokenless workload
identities. The low stage can read the exact benign marker through the owned
Service before policy. The native ingress rule stops that path twice in
succession while the high-stage peer still reads the marker. The test verifies
the Service's Ready endpoint and treats unexpected transport outcomes as
fixture errors.

The native API separately denies the low-stage identity access to the exact
fixture ConfigMap and permits the narrowly bound high-stage peer. Real
orchestrators, artifact stores, runtimes, and production deployment scope
require separate evidence.

## Verify an adopting implementation

Inventory all stage namespaces, Services, endpoints, identities, and alternate paths. Apply and verify default-deny plus narrowly scoped ingress and API authorization. Test the actual CNI and artifact backends from both authorized and unauthorized stage identities. The fixture verifies native NetworkPolicy and API denials for one topology. It does not establish production CNI enforcement or orchestration coverage.
