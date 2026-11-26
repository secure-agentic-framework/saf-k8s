# SAF-K8S-0704-002 — Cloud, Kubernetes API and Pod network boundaries

From the framework checkout, run the disposable comparison.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0704-002 --docker-context desktop-linux
```

From the lab checkout, invoke `python3 lab.py` with the same arguments.
Two owned clients initially reach the marker. Destination ingress allows
only the named source, and a separate egress policy can still deny that
same source. With both directions aligned, only the authorized path
returns the expected marker. A separate native API request verifies
the approved API reader and the denied comparison identity.

## Verify the deployed layers independently

1. Inventory intended provider node and subnet paths, API endpoint
   sources and Pod ingress and egress. Record source, destination,
   direction, network and protocol, service identity, owner, policy
   authority and approved exceptions.
2. Record actual managed API mode and endpoint, routing, firewall
   configuration, approved client locations, and the actual CNI:
   version, enabled policy features, address families, covered nodes
   and alternate interfaces. Identify how each control decision is
   enforced and logged.
3. From approved test sources, compare one allowed and one refused
   inert flow for each covered boundary. Check the expected API
   network endpoint and TLS identity from the intended source, and
   then check Kubernetes authentication and authorization separately.
4. Repeat the workload comparison for actual selected Pods and both
   policy directions. Retain sanitized effective provider settings,
   Kubernetes policy status and exact observed decision points.
   Repeat after material topology, provider or CNI changes.

[Kubernetes NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/),
[Amazon EKS API endpoint access](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html),
[GKE network isolation](https://cloud.google.com/kubernetes-engine/docs/concepts/network-isolation),
and [AKS control-plane networking](https://learn.microsoft.com/en-us/azure/aks/plan-control-plane-networking).
