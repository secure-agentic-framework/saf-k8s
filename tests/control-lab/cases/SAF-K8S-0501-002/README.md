# SAF-K8S-0501-002 — Cross-namespace isolation and DNS

```sh
python3 lab.py test SAF-K8S-0501-002 --docker-context desktop-linux
```

Three owned clients can reach both HTTP markers before policy. A single
NetworkPolicy peer requires the approved namespace label and the approved
Pod label. Matching only either label leaves the same live listener
unreachable. The approved client still retrieves its exact marker.

Client egress isolation blocks resolution of the case-owned Service. A
narrow CoreDNS rule restores its DNS lookup while the HTTP port stays
blocked. A separate scoped application rule restores the exact HTTP
response. Both listeners are healthy during the final check.

This covers three namespaces under bundled kindnet, IPv4 TCP/8080 and
the standard resolver path to CoreDNS. Verify TCP DNS independently if
required, along with production monitoring, system flows, label authority,
CNI behavior, and review cadence.

[Kubernetes NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) ·
[Kubernetes DNS debugging](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/dns-debugging-resolution/)
