# SAF-K8S-0502-001 CNI security selection

Run this case with Kind v0.32.0, Docker, kubectl and Helm.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0502-001 --docker-context desktop-linux
```

The case owns two disposable single-node Kubernetes v1.36.1 clusters. It runs the same workloads, namespace selectors, policies and TCP marker requests with bundled kindnet and with Cilium 1.20.5. Both markers respond before enforcement. After enforcement the inference marker is denied and the allowed pipeline marker remains reachable. The fixture also checks structured Cilium Hubble JSON for the exact local endpoints, TCP port, egress direction, forwarded verdict and policy-denied reason.

The synthetic selection profile specifically requires the embedded Cilium Hubble observer interface. The stock kindnet comparison has no Cilium agent and therefore cannot supply that interface. A deployment can approve another observer integration and verify its evidence separately. The lab records both selection decisions in `selection-record.json` and the matched Hubble flow records in `cilium-hubble-receipts.json`.

The production review also needs the approved selection matrix, workload-path coverage for encryption and FQDN/L7 rules, observed performance, provider constraints, and evidence for any compensating controls. The fixtures evaluate their own local Pod traffic.

[Kubernetes NetworkPolicy v1.36](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) and [Cilium Hubble](https://docs.cilium.io/en/stable/observability/hubble/index.html).
