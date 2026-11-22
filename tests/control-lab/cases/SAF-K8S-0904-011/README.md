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
