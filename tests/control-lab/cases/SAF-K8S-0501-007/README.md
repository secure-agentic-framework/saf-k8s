# SAF-K8S-0501-007 — East-west AI workload traffic monitoring

From the framework repository, run:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0501-007 --docker-context desktop-linux
```

Use Kind v0.32.0, Helm 3.13 or newer and a Linux Kind environment meeting Cilium requirements. The runner provisions Kubernetes v1.36.1 with the default CNI disabled. The case verifies the content digest of the pinned Cilium 1.20.5 chart from Quay, installs it into the disposable cluster, and waits for the Node and local Hubble observer. No relay or UI is required.

- **Red.** The training client reaches the inference and pipeline HTTP fixtures before policy. Hubble must record the exact paths and destination port reaching the destination endpoint at egress.
- **Green.** Default-deny policies block the training-to-inference path. Both the workload timeout and a new egress Hubble `DROPPED` event with `POLICY_DENIED` must corroborate that result.
- **Permitted.** The allowed training-to-pipeline path still returns its marker and produces a new `FORWARDED` flow.

The case uses only scoped Hubble records from three owned namespaces. The retained `hubble-events.json` includes the matching egress events. Source-endpoint traces occur before the final egress decision, so the evidence uses `TO_ENDPOINT` for forwarded traffic and the policy drop reason for denied traffic. The fixed segment rule demonstrates attribution for this lab. Production anomaly models, additional segments including notebooks, encrypted visibility, and collection, retention, and alerting in a SIEM require separate evidence.

[Cilium v1.20 Kind installation](https://docs.cilium.io/en/v1.20/installation/kind/) · [Cilium v1.20 Hubble setup](https://docs.cilium.io/en/v1.20/gettingstarted/hubble_setup/) · [Kubernetes v1.36 NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
