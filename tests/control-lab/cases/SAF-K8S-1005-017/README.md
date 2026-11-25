# SAF-K8S-1005-017

The case uses Kubernetes v1.36.1 on a disposable two-node Kind v0.32.0 cluster. Fixed HTTP
markers from two mock Services establish healthy cross-node paths. The test observes the
effect of ingress and egress independently, then confirms exact paired namespace and Pod
selectors permit the approved recovery path. An ordinary client, a same-label client in
another namespace, and the unrelated Service remain fenced.

Separately, a recovery identity initially cannot read the fixture receipt. A named Role
and binding allow the exact read while an unrelated object remains forbidden. Two new
credentials bind to empty, case-owned marker Secrets. TokenReview verifies the old
credential is invalidated only after its marker is retired and the replacement remains
valid. The receipts record outcomes without retaining credential values.

These checks establish scoped network, authorization and bound credential behavior in
Kind. Production CNI, control-plane or node paths, host networking, broader credential
classes, hardware, and organizational recovery procedures require separate review.

- [Kubernetes NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Kubernetes Service Accounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)
- [Kind v0.32.0](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0)

## Verify an adopting implementation

Map the recovery identity, namespaces, nodes, CNI policy
selectors, control-plane/host-network paths, mounted devices, and required
services. In an approved recovery exercise, prove exact allowed traffic and
receipt access while ordinary and same-label neighboring paths remain denied.
Exercise provider and Kubernetes credential replacement/revocation, validate
old-credential denial at every relying party, and record the replacement,
retirement, and rollback owner.
