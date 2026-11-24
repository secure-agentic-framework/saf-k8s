# SAF-K8S-0202-009 — Container runtime secure baseline settings

```sh
python3 lab.py test SAF-K8S-0202-009 --docker-context desktop-linux
```

The disposable Kind node runs containerd v2.3.1. The case observes a
dedicated Unix diagnostic listener, clears its address, and verifies that
the listener disappears. A case-owned configuration import keeps an
approved metrics endpoint bound to loopback. The case checks only the HTTP
response status for metrics and uses socket metadata for diagnostics.
Removing the import and clearing the metrics setting removes that listener.
The explicit local CRI socket still reports CRI v1 and runtime readiness,
and a new restricted Job completes. The case then restores its original
profile and removes the import.

## Verify an adopter deployment

1. Inventory the kubelet and runtime versions, runtime type, node image,
   service owner and provider responsibilities for each applicable pool.
   Identify the effective kubelet CRI endpoint.
2. Inspect the loaded runtime service, its ordered drop-ins, actual config
   path, imports and any socket unit or service overrides. Retain the
   reviewed profile and relevant fields from the effective config. Match
   settings to the runtime's exact release and schema. Containerd config
   v4 uses separate server plugins for gRPC, debug and metrics.
3. Compare the approved interface inventory with observed Unix and TCP
   listeners and their owning services. Required CRI must be reachable
   from the kubelet. Optional diagnostics and metrics should be absent
   unless approved. Record listener addresses, access restrictions, owner,
   reason, expiry and evidence for each exception. Use listener metadata
   for debug and keep profiling payloads out of the evidence.
4. On an authorized staging or canary node, verify the required endpoint
   speaks the expected CRI version and is ready. Schedule a fresh,
   representative workload and retain its startup result. Rehearse the
   supported rollback and verify recovery.
5. Obtain version- and pool-specific evidence for managed or alternate
   runtimes. Record settings that are outside your visibility as unverified
   and identify the party that can attest to them.

- [containerd v2.3.1 configuration](https://github.com/containerd/containerd/blob/v2.3.1/docs/man/containerd-config.toml.5.md)
- [Kubernetes v1.36 Container Runtime Interface](https://v1-36.docs.kubernetes.io/docs/concepts/containers/cri/)
- [Kubernetes v1.36 runtime configuration](https://v1-36.docs.kubernetes.io/docs/setup/production-environment/container-runtimes/)
