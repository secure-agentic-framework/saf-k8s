# SAF-K8S-0203-015 — Endpoint retirement and response hop limits

```sh
python3 lab.py test SAF-K8S-0203-015 --docker-context desktop-linux
```

Two owned Kubernetes Services expose a harmless TCP marker. The runner
retires one route by removing its ready EndpointSlice backends, verifies
that the other route stays reachable, and restores the original route.
In the same disposable cluster, an owned IPv4 UDP marker uses Linux socket
TTL controls. It returns an ordinary response across the two-node path.
With TTL one, the origin records that it sent the response and a loopback
client still receives it, while the peer-node client times out. Restoring
the higher limit recovers the same routed flow.

These are independent Service and Linux routing demonstrations. The test
does not contact a cloud metadata service or apply provider settings.

## Verify deployment applicability and evidence

1. Inventory provider product, node pools, endpoint and protocol versions,
   applicable address families and routes, intended callers, and required
   node or workload dependencies. Record the owner and approved exceptions.
2. Collect applied read-only provider configuration for the actual
   instances or pools and relevant defaults. For EC2, review
   `HttpEndpoint`, `HttpTokens`, `HttpPutResponseHopLimit`, and
   `HttpProtocolIpv6` independently. The EC2 hop-limit option scopes the
   IMDSv2 PUT response. For AKS or GKE, identify the distinct supported
   metadata restrictions, ownership, node-image rollout, and workload
   identity configuration.
3. Verify each permitted and denied caller class and IP family using
   harmless traffic in approved staging or a provider-supported assessment.
   Retain route and firewall evidence, actual response behavior, and an
   independent successful dependency check. A hop-limit setting by itself
   supplies evidence only for its applicable response and route.
4. Document evidence for provider-managed nodes, host or node-local
   behavior, routed hops and DNS or proxy-dependent paths separately. Verify
   rollback and monitor restored dependencies before closing exceptions.

[EC2 instance metadata options](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html) ·
[AKS IMDS restriction](https://learn.microsoft.com/en-us/azure/aks/imds-restriction) ·
[GKE workload identity](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/workload-identity)
