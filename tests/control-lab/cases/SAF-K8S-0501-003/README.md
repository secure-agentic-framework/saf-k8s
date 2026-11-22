# SAF-K8S-0501-003 — Workload egress to approved destinations

```sh
python3 lab.py test SAF-K8S-0501-003 --docker-context desktop-linux
```

A benign client first reaches three live address and port combinations on
two owned Docker peers outside the Kubernetes cluster. A workload-scoped
NetworkPolicy allows one peer IPv4 /32 and TCP/8080. The same client still
retrieves the approved marker, while the other IP and the alternate port
on the approved IP are blocked. Both denied listeners independently return
their markers locally. The fixture removes the peers and bridge afterward.

A second phase repeats the default-deny and permitted-route observations
for two owned in-cluster listeners. The selected namespace and Pod labels
restore only the approved TCP route.

The fixture covers kindnet IPv4 and direct connections on the test-owned
networks. Verify FQDN filtering on the intended CNI, provider routing and
egress gateways, DNS controls, and deployed external-service inventory
separately.

[Kubernetes NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
