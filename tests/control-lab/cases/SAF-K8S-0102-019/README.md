# SAF-K8S-0102-019 — Verify access to etcd client and peer listeners

Run `python3 tests/control-lab/lab.py test SAF-K8S-0102-019 --docker-context desktop-linux` from the framework checkout. The case uses three Kind control planes and one worker.

Seven checks compare separate workload marker paths and actual kubeadm etcd listeners. The fixture inventories three live members and observes worker and Pod connections before a case-owned node input restriction. It then verifies refused connections and native drop counters on each peer. Authorized TLS still completes for all six directed etcd member pairs and verifies each server's exact public certificate. Local clients, membership, API readiness and marker reads stay healthy. The case restores its narrow node rules and deletes the cluster.

## Verify deployed etcd paths

1. Inventory actual client and peer listeners, addresses, protocols, ownership and expected members. Include managed, external, backup, automation and administrative paths where available, and document which surfaces the adopter can inspect or control.
2. Verify the effective host and infrastructure rules or provider controls for each endpoint class. Check exact allowed and denied decisions from approved test origins, including workload, worker and administrative paths. Use workload NetworkPolicy evidence for the paths it actually selects.
3. Verify trusted client and peer TLS names, CA and credential authority separately from connectivity and operation authorization. Record authorized exceptions and approval, and test normal health, quorum and an approved restoration path during a change.
4. Preserve sanitized configuration version, topology, selected test locations, effective results and coverage for each environment, including applicable address families and operational listener variants.

- [Kubernetes NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
- [kubeadm implementation details](https://v1-36.docs.kubernetes.io/docs/reference/setup-tools/kubeadm/implementation-details/)
- [etcd 3.6 transport security](https://etcd.io/docs/v3.6/op-guide/security/)
