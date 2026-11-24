# SAF-K8S-0201-012 — Kubelet anonymous access and read-only port lockdown

From this control lab directory, run:

```sh
python3 lab.py test SAF-K8S-0201-012 --docker-context desktop-linux
```

The disposable Kind v1.36.1 lab checks the control-plane and worker kubelets.
Each has anonymous authentication disabled, a secure TCP listener, and no
TCP 10255 read-only listener. Each returns HTTP 401 to a TLS-verified,
credentialless HTTPS health request and returns a healthy response through
the authenticated Kubernetes API proxy. The test retains status and TLS
verification results. It leaves the legacy listener disabled.

## Verify an adopter deployment

1. Inventory Kubernetes version, provider and node pools for production,
   sensitive and production-connected clusters. Include every control-plane,
   worker, GPU and inference pool. Record the nodes each observation covers.
2. Use authorized effective-configuration access on each applicable node.
   Verify `authentication.anonymous.enabled` is `false` and
   `readOnlyPort` is zero. Retain dated redacted observations and the
   approved profile revision. Verify separate secure-endpoint authorization
   using SAF-K8S-0201-011.
3. From an approved observation point, use the trusted serving identity and
   CA for a credentialless HTTPS check of `/healthz`. Expect HTTP 401.
   Verify a trusted API proxy health request succeeds. Confirm TCP 10255
   has no listener with approved node-level visibility. Retain only the
   observed statuses, trust verification and listener evidence.
4. Review actual security-group, firewall, and routing policy for the
   applicable pools and observation points. Retain scoped policy evidence.
   Local listener inspection covers the node's own socket state.
5. For a managed service, identify who operates each node class and retain
   applicable product, version and node-class documentation or attestation
   and dated customer-visible network evidence. Record unavailable settings
   as unverified. Recheck after node image, version or network changes.

An accelerator device plugin's local Unix socket and the kubelet's network
listeners are distinct interfaces. Use the same endpoint checks for accelerator
pools. Where using CIS-based tooling, select the benchmark edition that applies
to the Kubernetes version and provider.

- [Kubernetes v1.36 kubelet authentication and authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)
- [Kubelet v1beta1 configuration](https://v1-36.docs.kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/)
- [Kubernetes v1.36 device plugins](https://v1-36.docs.kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/device-plugins/)
