# SAF-K8S-0404-007 Scheduled certificate renewal

Run by control ID on fresh Kind. A digest-pinned cert-manager controller
schedules two leaves at different times. The early certificate renews
with a new key before expiry without a specification change. The
ordinary-schedule control keeps its original leaf. A live service reloads
its mounted certificate and a trust-verifying client observes the
replacement on the wire.

The exact rollout and reload pattern belongs to this workload. Assess
the API server, etcd, kubelets, webhooks, meshes, and external issuer
paths independently.

- [cert-manager Certificate renewal and reissuance](https://cert-manager.io/docs/usage/certificate/)
- [Kubernetes Secret volume updates](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/secret/)
