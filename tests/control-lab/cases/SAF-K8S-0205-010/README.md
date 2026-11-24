# SAF-K8S-0205-010 Node firewall paths

Two disposable Kind nodes test exact input and output hooks, interfaces,
IPv4 addresses and TCP ports on owned paths. The worker connects to three
harmless dynamic marker listeners on the control-plane node and also checks
the direct Kubernetes API TLS path against the cluster's CA. The two
host rules block different fixture tuples, their counters attribute the
drops, and removing each restores the affected marker. The case records
routed interfaces, actual rules, counters, health and rollback observations.

```sh
python3 lab.py test SAF-K8S-0205-010 --docker-context desktop-linux
```

## Verify a governed node boundary

1. Inventory node profiles, owners and roles, applicable interfaces and IP
   families, CNI, routes, translation, allowed inbound and outbound source
   and destination classes, protocol/port, rate requirements and exceptions.
   Identify host, provider and workload enforcement separately. Record needed
   control traffic such as API, kubelet, DNS, CNI and health probes.
2. Obtain read-only effective rule and provider exports and identify which
   hooks, interfaces and translated tuple each rule observes. For each approved
   boundary record applicable source, destination, interface, family, protocol,
   port, owner, exception expiry and logging or counter source.
3. In matching disposable infrastructure run known-marker flows only between
   explicitly owned endpoints. Compare baseline, input only, output only,
   combined and rollback. Record the approved flow and negative decisions.
   Tie denied observations to attributable counters or equivalent evidence
   and verify actual node-to-control-plane and other required paths remain
   healthy. Repeat on the families and profiles used by the deployment.
4. Retain the observed route, rule selectors, evidence of the applicable
   health paths, change audit and rollback outcome. Provider-only paths and
   additional protocol or rate requirements need their corresponding
   configuration and observations.

- [nftables reference](https://netfilter.org/projects/nftables/manpage.html)
- [Kubernetes v1.36 control plane and node communication](https://v1-36.docs.kubernetes.io/docs/concepts/architecture/control-plane-node-communication/)
