# SAF-K8S-0501-006 — Cross-cluster transport identity and network isolation

```sh
python3 lab.py test SAF-K8S-0501-006 --docker-context desktop-linux
```

The case creates two disposable Kind clusters with an internal bridge between
their owned nodes. A synthetic client in the source cluster submits a harmless
`GET /health` to the peer cluster. Each API command selects its own context
and temporary kubeconfig.

The same peer route first accepts a request without client authentication. The
client rejects a mismatched server hostname. After mutual TLS is enabled, a
missing certificate fails at TLS, a trusted wrong URI SAN receives 403, and the
approved certificate stays usable.

The source client can initially reach two ports on the peer cluster.
NetworkPolicy preserves the approved peer IP and TCP port. It denies the
alternate port while an independent client retains access to it. The fixture
correlates bounded client and peer events for the permitted flow and checks
that the denied flow never reaches the peer HTTP handler. Both clusters and
the bridge are removed.

Deployed mesh, trust rotation, provider networking, and operational flow
collection require separate evidence.

[Kubernetes v1.36 NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) ·
[Kubernetes Multi-Cluster Services API](https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api) ·
[Python TLS verification](https://docs.python.org/3/library/ssl.html#security-considerations)
