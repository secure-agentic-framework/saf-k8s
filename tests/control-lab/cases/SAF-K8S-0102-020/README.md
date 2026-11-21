# SAF-K8S-0102-020 — etcd certificate maximum validity period enforcement

```sh
python3 lab.py test SAF-K8S-0102-020
```

The harness creates the pinned stock `kindest/node:v1.36.1` cluster. The case
records public validity dates for its kubeadm-generated etcd server, etcd peer,
and kube-apiserver etcd-client certificates. It then creates a second node from
the same pinned image, using the included kind patch to set kubeadm
`ClusterConfiguration.certificateValidityPeriod: 719h55m`. It checks each
deployed certificate's `notBefore`, `notAfter`, duration, current validity, and
chain to that cluster's etcd CA. The configured cluster's `/readyz` response
provides a positive runtime check.

The red result is the measured stock validity exceeding the example 720h
organization maximum. Green requires all three configured leaf certificates to
have a lifetime of exactly 720h, current, and trusted by the local etcd CA. The positive result
requires both profiles' observed certificates to remain current and trusted and
the configured API server to report ready. Only OpenSSL public-certificate date
and verification output is collected from nodes; no private key or credential
contents are read or logged.

Kubeadm v1.36.1 backdates leaf certificate start dates by five minutes. A
719h55m nominal duration allows the measured interval between NotBefore and
NotAfter to meet the 720h maximum. Kubeadm v1.36 documents `certificateValidityPeriod` as the validity period for
non-CA certificates it generates and gives the default as 8760h (one year).
It documents a separate 87600h default for generated CA certificates. This case
uses a 720h example policy, not a claim that Kubernetes prescribes that maximum.
It evaluates a newly initialized single-node kind cluster; it does not test
renewal, upgrades, multi-node propagation, external etcd, pre-supplied
certificates, external CA operation, or a separately managed issuer. Kubeadm's
certificate management documentation explicitly places external-CA-signed
certificates outside kubeadm management.

## Versioned primary sources

- [Kubeadm Configuration API v1beta4, Kubernetes v1.36](https://v1-36.docs.kubernetes.io/docs/reference/config-api/kubeadm-config.v1beta4/): `ClusterConfiguration.certificateValidityPeriod` and its 8760h default; separate CA validity field and default.
- [Certificate Management with kubeadm, Kubernetes v1.36](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/): validity configuration, external CA boundary, and certificate roles including `apiserver-etcd-client`, `etcd-peer`, and `etcd-server`.
- [Kubernetes v1.36.1 kubeadm constants](https://github.com/kubernetes/kubernetes/blob/v1.36.1/cmd/kubeadm/app/constants/constants.go): release-tagged source defaults for non-CA and CA validity.
- [Kubernetes v1.36.1 kubeadm certificate generation](https://github.com/kubernetes/kubernetes/blob/v1.36.1/cmd/kubeadm/app/phases/certs/certlist.go#L61-L74): release-tagged generation and certificate-role source.
