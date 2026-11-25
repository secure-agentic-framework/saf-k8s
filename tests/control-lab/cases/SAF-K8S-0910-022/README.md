# SAF-K8S-0910-022 cross-cluster network and operation authorization

Run from the framework checkout:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0910-022 --docker-context desktop-linux
```

Two independent Kind clusters use one private test bridge and one dynamically
assigned peer NodePort. Three approved fixture certificates can establish the
baseline route. Default-deny egress on the source cluster then prevents all
three test Pods from reaching the peer, and the destination records no
additional requests.

A separate rule restores connectivity for two selected source Pods to the
inspected peer node address and exact NodePort. The third caller keeps a
trusted certificate and stays blocked at egress. On that same route, the
destination separately checks the mTLS source identity against the requested
operation. The two permitted peers can run only their assigned operation.
The destination records the exact allow and deny decisions for that phase.

## Verify an adopting implementation

1. Enumerate the approved source workloads, namespaces, selectors, endpoints,
   protocols and operations. Inspect every governed route and alternate path,
   including the effective CNI and any address or port translation.
2. Exercise default-deny with approved synthetic clients, then allow just the
   documented destination and port for the expected workloads. Verify the
   negative path reaches no peer application and the authorized comparator
   still works under the exact policy.
3. Separately prove the peer verifies source and destination trust and denies
   operations outside each identity's authority. Retain effective policy,
   endpoint and authentication identities, decisions and an exception review.
4. Evaluate additional interfaces, address families, provider gateways and
   global monitoring under the environment's own controls.

[Kubernetes v1.36 NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
and [Kubernetes Service source IP](https://v1-36.docs.kubernetes.io/docs/tutorials/services/source-ip/).
