# SAF-K8S-0501-006 — Multi-cluster transport identity

```sh
python3 lab.py test SAF-K8S-0501-006 --docker-context desktop-linux
```

The case creates two disposable Kind clusters. An internal Docker bridge
connects only their owned nodes for the test path. Each API command names
the exact cluster context and temporary kubeconfig. A synthetic client in
one cluster sends a harmless `GET /health` to the peer cluster's NodePort.

Before enforcement, the service accepts a request without a client
certificate. The client uses the same trusted CA and TLS hostname checks
throughout. A mismatched server hostname is rejected.

The fixture switches the same NodePort to mandatory mutual TLS and waits
for removal of the baseline server. The missing client certificate fails
the TLS handshake, a valid certificate with a different URI SAN gets
HTTP 403, and the same approved client still gets HTTP 200. Both server
revisions are selected explicitly when verifying bounded flow records.
The case retains no certificate or key material, request bodies, or
response bodies. The bridge and independent cluster are cleaned up.

MCS defines export and discovery primitives. Authenticated peer identity
and network segmentation require separately enforced policy. Deployed
mesh, MCS, L3/L4 controls, provider networking, key lifecycle and unified
multi-cluster flow reporting require additional evidence.

[Kubernetes Multi-Cluster Services API](https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api) ·
[Python TLS verification](https://docs.python.org/3/library/ssl.html#security-considerations)
