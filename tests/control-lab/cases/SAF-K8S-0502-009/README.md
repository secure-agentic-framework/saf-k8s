# SAF-K8S-0502-009 — Service address capacity and monitoring

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0502-009 --docker-context desktop-linux
```

The disposable Kubernetes v1.36.1 fixture reconciles each Service ClusterIP to a native IPAddress object and its Service parent reference. It measures free addresses in the Ready IPv4 ServiceCIDR ranges. The node's assigned PodCIDR must also sit inside the configured Pod subnet and be disjoint from the Service range.

The case checks a healthy baseline with no warning, consumes addresses through case-owned Services, and verifies an Event when exactly two addresses remain. It fills the original range and verifies the expected allocation rejection while the original Service continues to answer. Adding a second ServiceCIDR lets the rejected request succeed, restores spare capacity and produces a retained recovery Event. The Events refer to the UID of the original or expanded test Service, and both Services must return the marker through cluster DNS at the end.

The test harness emits the Events based on the live allocation inventory. Its threshold of two addresses is a fixture setting. In an adopter environment, inventory Service, CNI Pod and node-prefix pools for each configured address family, record capacity and utilization from each allocator, and verify a justified threshold, recovery and notification delivery for each applicable pool. Check CNI Pod exhaustion and node prefix exhaustion separately in approved nonproduction. Include all applicable provider-managed and secondary pools.

[Kubernetes v1.36 ServiceCIDR expansion](https://v1-36.docs.kubernetes.io/docs/tasks/network/extend-service-ip-ranges/) · [Kubernetes v1.36 Events v1 API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/events/event-v1/)
