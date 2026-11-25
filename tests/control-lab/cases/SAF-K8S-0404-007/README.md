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

## Adopter verification

1. Inventory deployed certificate roles, each approved issuer, issuance approval and the exact consuming workload, service or endpoint.
2. Record trigger, permitted renewal window and approved key policy for each class. Use the actual controller and observe a new valid certificate and applicable key replacement while the intended endpoint remains healthy.
3. Confirm consumer reload and successful peer verification, including active certificate identity and chain. Retain a separate comparison for incorrect trust, unavailable issuers and the recovery path.
4. Retain version, supported provider capability, trigger sequence, reload result, failure and fallback evidence, and ownership. Recheck after issuer, controller, trust or consumer changes.
