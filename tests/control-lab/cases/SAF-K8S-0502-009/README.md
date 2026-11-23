# SAF-K8S-0502-009 — Service address capacity

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0502-009 --docker-context desktop-linux
```

The case creates a disposable Kubernetes v1.36.1 cluster with a deliberately small IPv4 service pool. It fills the available addresses and checks the allocator's rejection while an existing Service still works. Adding a second pool lets the same create request succeed. Both Services must continue to return the marker through cluster DNS. The test also checks that the node's PodCIDR is within the cluster Pod subnet and disjoint from the service subnet.

The test verifies the Kubernetes Service allocator. Deployed CNI Pod pool sizing, node CIDR capacity, IPv6, monitoring and alerts need separate evidence. [Kubernetes v1.36 ServiceCIDR expansion](https://v1-36.docs.kubernetes.io/docs/tasks/network/extend-service-ip-ranges/)
