# SAF-K8S-0205-007 Node firewall and NetworkPolicy compatibility

On two disposable Kind nodes, three owned clients exercise both the server Pod's
IPv4 address and a ClusterIP with a different frontend port. The receiver's
scoped nftables forward rule matches one source at the translated backend port.
An ingress NetworkPolicy denies a different source. The case records the path
matrix before either control, with the node firewall alone, with both active,
with workload policy alone, and after rollback. It records the nftables packet
counter after each path and verifies in-cluster DNS and API-server readiness in
each phase. It writes effective rules, policy selectors, profile versions, and
socket outcomes to `firewall-compatibility-observations.json`.

```sh
python3 lab.py test SAF-K8S-0205-007 --docker-context desktop-linux
```

## Verify a node profile

1. Inventory the Kubernetes and kernel versions, node image, CNI and proxy
   mode, host firewall owner, address families, interfaces, routes, NAT and any
   encapsulation. Map each required or denied flow to its enforcement owner,
   expected source and destination after translation, protocol, and policy
   hook. List DNS, API, health probes and other required platform traffic.
2. Inspect the active policy and listener state in each governed profile. Use
   `kubectl get networkpolicy -A -o yaml`, `kubectl get nodes -o wide`, the
   CNI and proxy configuration, and approved firewall rule and counter exports.
   Record provider-owned boundaries using provider configuration and flow
   records. Identify the owner when a path is outside the operator's visibility.
3. In an equivalent disposable environment, run known-marker probes between
   authorized sources and destinations. Include direct Pod, Service, and any
   applicable node or provider path. Record outcomes before the change, after
   each control by itself, with the controls together, and after rollback.
   Capture attributable counters or decisions, DNS and API health, and continued
   success of the required flows. Repeat for applicable traffic families,
   protocols, directions, and node profiles.
4. Retain the matrix, timestamps, profile and policy identities, effective
   rule selectors and relevant decisions, service health, and rollback result.
   Mark a path unverified until the matching policy owner can supply the
   missing observations. Repeat after changes to routing, CNI, proxy, node
   images or policy.

The runnable fixture exercises routed IPv4 TCP with kindnet, kube-proxy in
iptables mode, and a private nftables table. Profile-specific evidence covers
other combinations, provider or host interfaces, and additional protocols.

- [Kubernetes v1.36 Network Policies](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Kubernetes v1.36 Service virtual IPs](https://v1-36.docs.kubernetes.io/docs/reference/networking/virtual-ips/)
- [nftables netfilter hooks](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks)
