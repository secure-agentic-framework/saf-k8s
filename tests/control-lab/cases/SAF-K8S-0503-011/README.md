# SAF-K8S-0503-011 — External traffic policy mode selection and tradeoff governance

```sh
python3 lab.py test SAF-K8S-0503-011 --docker-context desktop-linux
```

The runner creates a Kubernetes v1.36.1 Kind cluster with two worker nodes
and separate loopback mappings to their NodePorts. The EndpointSlice shows
one Ready backend on worker A. Three requests through each worker return
the same marker with `externalTrafficPolicy: Cluster`. The case patches the
existing Service to `Local` while retaining its UID, ports, selector and
backend. Three requests on worker A still return the marker. Three requests
on worker B, which lacks a local endpoint, receive no HTTP response.

The scoped admission policy checks the example decision record on a Service
update. Before enforcement, the API accepts a dry-run mode switch without a
record. Afterward it requires the recorded mode to match the proposed
Service spec and requires a routing rationale. An approved shape passes
dry-run while the saved Service stays in Local mode.

A Service owner can use the measured behavior when documenting the choice.
Cluster keeps an entry node usable when its backend is on a different node.
Local limits forwarding to node-local endpoints and therefore depends on
where Ready endpoints run. Deployment follow-up covers evidence that all
externally exposed Services have an approved decision, actual load balancer
health checks, and recovery during endpoint movement. Client source address
preservation has its own control, SAF-K8S-0503-012.

- [Kubernetes v1.36 external traffic policy](https://v1-36.docs.kubernetes.io/docs/reference/networking/virtual-ips/#external-traffic-policy)
- [Kubernetes v1.36 source IP behavior](https://v1-36.docs.kubernetes.io/docs/tutorials/services/source-ip/)
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)

## Adopter verification

Confirm each deployed NodePort/LoadBalancer mode against a recorded routing decision. Inventory endpoint topology and check that provider health checks remove nodes without local endpoints when `Local` is selected. Exercise approved paths on both a node with a local endpoint and one without; retain response and health-check evidence. Record failure/recovery behavior and review mode changes against the stored rationale.
