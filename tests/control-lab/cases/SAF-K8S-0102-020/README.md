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
It evaluates one newly initialized single-node Kind profile and its selective
renewals. Upgrades, multi-node propagation, external etcd, pre-supplied
certificates, external CA operation and independent issuers require their own
evidence. Kubeadm's
certificate management documentation explicitly places external-CA-signed
certificates outside kubeadm management.

## Versioned primary sources

- [Kubeadm Configuration API v1beta4, Kubernetes v1.36](https://v1-36.docs.kubernetes.io/docs/reference/config-api/kubeadm-config.v1beta4/): `ClusterConfiguration.certificateValidityPeriod` and its 8760h default; separate CA validity field and default.
- [Certificate Management with kubeadm, Kubernetes v1.36](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/): validity configuration, external CA boundary, and certificate roles including `apiserver-etcd-client`, `etcd-peer`, and `etcd-server`.
- [Kubernetes v1.36.1 kubeadm constants](https://github.com/kubernetes/kubernetes/blob/v1.36.1/cmd/kubeadm/app/constants/constants.go): release-tagged source defaults for non-CA and CA validity.
- [Kubernetes v1.36.1 kubeadm certificate generation](https://github.com/kubernetes/kubernetes/blob/v1.36.1/cmd/kubeadm/app/phases/certs/certlist.go#L61-L74): release-tagged generation and certificate-role source.

## Issuance policy during renewal

After the original readiness check, run the three named kubeadm renewals with
the same duration policy. Each replacement leaf has a different fingerprint,
the exact expected validity interval, current validity and trust under the
case-owned etcd CA. This observes newly written certificate files. Service
adoption requires comparing the renewed leaf on the actual connection and
following the documented process reload or rollout procedure.

- [Kubernetes v1.36 kubeadm certs renew reference](https://v1-36.docs.kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-certs/)

## Adopter evidence


For every cluster and etcd member, bind the approved maximum to the effective
issuer/profile revision and record applicability, exception approval, issuer
and role, public validity interval, chain/trust result, renewal event, and
evidence date. Cover server, peer and API-server-client certificates after
issuance, renewal, upgrades and relevant profile changes. Use a versioned
periodic inventory to detect certificates that predate the policy or were
installed from supplied files. Keep private keys out of evidence.

For external CAs, CSR signers, external etcd, provider-managed clusters or
alternate profiles, obtain issuer-specific documentation/attestation and public
leaf measurements. A kubeadm fixture cannot show that those systems enforce
the cap. The 0102-021 expiration-alert case is complementary: alerting and
telemetry do not prove issuance or renewal validity caps.
