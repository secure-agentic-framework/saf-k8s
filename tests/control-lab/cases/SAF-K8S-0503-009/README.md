# SAF-K8S-0503-009 — CoreDNS and upstream resolver hardening

```sh
python3 lab.py test SAF-K8S-0503-009 --docker-context desktop-linux
```

The Kubernetes v1.36.1 Kind cluster starts with kubeadm's CoreDNS add-on
disabled. The test confirms API readiness and absence of the stock CoreDNS
Deployment and DNS Service. It then installs a dedicated CoreDNS v1.14.2
instance with a digest-pinned image.

Before configuration, the same reserved test query reaches only the
unapproved local resolver. A genuine ServiceAccount cannot update the
Corefile until it receives an RBAC grant scoped to that named ConfigMap.
The granted identity applies the change and is still denied on an
unrelated ConfigMap. The runner rolls out the new configuration, waits for
the Service's routing to converge, and checks that the exact query now
reaches only the approved resolver.

The case also verifies the native Kubernetes Service lookup, one cache
hit through unchanged upstream query counts, and separate health and
readiness endpoints. The loop plugin is configured and startup remains
healthy. Both upstreams are disposable fixtures. Deployment evidence
covers NodeLocal DNSCache, resolver approval and redundancy, other cache
settings, and actual configuration-change governance.

- [Kubernetes v1.36 kubeadm DNS add-on configuration](https://v1-36.docs.kubernetes.io/docs/reference/config-api/kubeadm-config.v1beta4/)
- [Kubernetes v1.36 DNS customization](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/dns-custom-nameservers/)
- [CoreDNS v1.14.2 plugins](https://github.com/coredns/coredns/tree/v1.14.2/plugin)
