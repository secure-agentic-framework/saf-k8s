# SAF-K8S-0205-004 Cilium policy enforcement

This case installs the pinned Cilium chart on two disposable Kind nodes.
It verifies cross-node IPv4 TCP and HTTP with case-owned Pods. Both clients can
reach the server before policy. Cilium adds a sender egress port restriction
and then a receiver ingress policy that matches the sender identity and sends
selected HTTP traffic to Envoy. The case compares actual marker responses,
checks the relevant kernel policy map entries, removes each policy, and
retains the effective path observations and time to observe convergence.

```sh
python3 lab.py test SAF-K8S-0205-004 --docker-context desktop-linux
```

## Verify an adopter profile

1. Record the governed Cilium and Kubernetes versions, node OS and kernel
   features, IP families, routing/encapsulation, Service and proxy mode,
   ingress and egress policy APIs, active features, and protocol limitations.
   Use the CNI support matrix and note the owner of other enforcement points.
2. In a disposable equivalent profile, pin workload identities and use owned
   endpoints. Assert the positive control reaches the marker before and after
   a policy change. Capture the active endpoint identities and policy
   revisions with `kubectl get ciliumendpoints -o yaml` and the provider's
   approved endpoint, policy-map, and proxy decision exports. Record the
   actual allow and deny results in each governed direction and path. A
   denied HTTP request and a transport-level denial are different outcomes.
3. Check convergence and rollback after a scoped policy or agent change.
   Record time of submission, endpoint realization, first stable set of
   observed decisions, permitted traffic continuity, and recovery. In a
   representative staging profile, review supported failure scenarios for
   node, agent and any companion proxy. Keep performance measurement separate
   using expected offered load, latency, throughput, resource use and errors.
4. Retain the effective decisions and unsupported paths by owner and repeat
   after changes to versions, features, workload selectors or topology.

The fixture exercises new connections on its pinned Kind VXLAN and Envoy
profile. Provider paths, disruption and workload performance remain
environment-specific verification.

- [Cilium 1.20.5 system requirements](https://docs.cilium.io/en/stable/operations/system_requirements/)
- [Cilium Layer 4 policy](https://docs.cilium.io/en/stable/security/policy/layer4/)
- [Cilium Layer 7 policy and Envoy](https://docs.cilium.io/en/stable/security/policy/layer7/)
