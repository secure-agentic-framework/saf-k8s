# SAF-K8S-0102-018 — etcd client and peer TLS authentication

Run from the lab root with Python, Kind, kubectl and a local Docker context.

```sh
python3 lab.py test SAF-K8S-0102-018 --docker-context desktop-linux
```

In SAF-K8S, use `python3 tests/control-lab/lab.py` with the same arguments.
The runner creates and deletes its own three-control-plane Kind cluster
using the digest-pinned Kubernetes v1.36.1 image.

The designated first member's live etcd manifest must enable client and peer
certificate authentication. Certificate-less TLS 1.3 probes to ports 2379
and 2380 verify the server identity before receiving the client-certificate
required alert. The native health-check client verifies its permitted
operation, and its peer credential successfully negotiates the peer channel.

The additional comparison resolves the actual names and HTTPS endpoints of
three Ready members. All three peer listeners refuse clients without a
certificate. Each member's existing credential completes a verified TLS
handshake to a different member in a directed cycle. The OpenSSL invocations
use credential paths inside the origin nodes and retain only stable receipt
predicates. API readiness remains available after the handshake probes.

## Adopter verification

Inventory each actual client and peer listener, member identity, expected
peer URL, effective peer authentication flags, and approved trusted CA.
Verify unauthorized and intended peer TLS behavior from approved origins.
Retain the actual expected identities and route decisions for each member.
Use applicable provider documentation or attestation for provider-owned
paths. Use the [certificate lifecycle case](../SAF-K8S-0102-014/README.md)
for the separate renewal and adoption behavior.

- [etcd v3.6 transport security](https://etcd.io/docs/v3.6/op-guide/security/)
- [Kubernetes v1.36 kubeadm certificate management](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/)
