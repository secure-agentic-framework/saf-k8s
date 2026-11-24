# SAF-K8S-0201-014 Kubelet serving certificate trust and expiry

From the framework root, run:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0201-014 --docker-context desktop-linux
```

This disposable Kubernetes v1.36.1 control-plane node starts with native
serving TLS bootstrap and a pending serving CSR from a fresh kubelet invocation.
The fixture verifies the
authenticated node identity, usage, and all requested DNS and IP names before
approving the exact owned request. The kubelet serves the resulting leaf. An
ordinary client verifies its CA and DNS identity, and the API server verifies
the kubelet using its configured CA for the metrics and workload-log paths.

A 150-second signing duration is reserved for the disposable case. The native
certificate TTL metric crosses a rehearsal threshold, a second serving CSR
is approved under the same identity policy, and the new leaf appears while the
first is still valid. The new leaf still works after the first expires.
Offline validation of the original public leaf exercises the wrong CA, wrong
DNS name and time after expiry. Retained evidence includes only identifiers,
certificate lifecycle timing and boolean observations.

## Verify your implementation

- Inventory relevant kubelet HTTPS endpoints, node pools, service ownership,
  consumers, and the DNS or IP identity each consumer expects. Verify the
  effective CA configured by the API server, collectors and any direct clients.
  Assess TLS for each intended request path using ordinary verified connections.
- For native serving CSR issuance, verify the effective server TLS bootstrap
  setting and the version's server rotation support. Check the exact signer,
  authenticated node identity, usages, and all IP/DNS SANs against the Node and
  trusted inventory before approval. Native kube-controller-manager signing
  still requires an explicit serving-CSR approval workflow. Verify scope and
  identity of the approving role and retain the approval decision.
- Track pending and rejected requests, expiry, observed live identity and
  remaining valid lifetime. Set a lead time suitable for the issuer, approval
  process and workload dependency. Rehearse pending requests, a replacement
  and failed trust validation in authorized staging. Confirm alert receipt,
  escalation ownership and a successful verified connection after replacement.
- For externally provided certificates, verify the effective file or provider
  source, renewal and activation on the listener, and current chain and SAN
  validation. For provider-operated nodes, retain current evidence for the
  named service, version and scope of rotation and TLS enforcement. Record an
  evidence gap where the exact scope or effective client verification is unavailable.
- Retain public metadata and approval evidence. Keep private credential files
  under the platform's approved protection and access procedures.

- [Kubernetes v1.36 serving CSR policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#kubernetes-signers)
- [Kubernetes v1.36 kubelet settings](https://v1-36.docs.kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/)
- [Kubernetes v1.36 metrics reference](https://v1-36.docs.kubernetes.io/docs/reference/instrumentation/metrics/)

The historical catalog revision selects the retained `external-ca.py` example.
Its receipt verifies an externally provisioned synthetic leaf and three offline
counterfactuals. The current revision selects the native renewal example.
