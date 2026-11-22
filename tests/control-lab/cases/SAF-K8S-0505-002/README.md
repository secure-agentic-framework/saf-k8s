# SAF-K8S-0505-002 — LoadBalancer, NodePort, and ExternalIP restriction policies

Run on a fresh, digest-pinned Kubernetes v1.36.1 Kind cluster with:

```sh
python3 lab.py test SAF-K8S-0505-002 --docker-context desktop-linux
```

The case uses native `ValidatingAdmissionPolicy` to deny `NodePort`,
`LoadBalancer`, and `spec.externalIPs` Service requests at CREATE and UPDATE.
Before activating policy, the same shapes must pass server-side dry-run in the
unenforced fixture namespace. After activation, each unauthorized shape must
receive the policy's stable denial message. Combined type-plus-ExternalIPs
requests and an ExternalIPs list containing an out-of-pattern address are also
denied.

One synthetic exception demonstrates the catalog's explicit-approval path. It
requires the `platform-exposure-owner` service account, the exact
`saf-k8s-0505-approved` namespace, the expected owner label and approval
annotation, and an `approved-*` Service name. That identity may submit each
exposure shape as server-side dry-run on both CREATE and UPDATE. Its
`externalIPs` values must all match
the reserved documentation prefix `192.0.2.0/24`; a different documentation
prefix is denied. The two actors authenticate with short-lived ServiceAccount
credentials and use the same fixture inputs against the API server. Requests
for NodePort, LoadBalancer, and ExternalIPs use server-side dry-run.

The only persisted Services are harmless `ClusterIP` fixtures with no selector,
so they have no endpoints. The case verifies the v1.36 `spec.externalIPs`
deprecation warning. Production follow-up covers routing, cloud load balancer
provisioning, managed admission ordering, namespace coverage, audit monitoring,
and approval governance.

## Pinned control and upstream sources

- [SAF-K8S-0505-002 at the lab's pinned catalog commit](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0505-002.md)
- [Kubernetes v1.36 Service documentation: External IPs](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/service/#external-ips)
- [Kubernetes v1.36 DenyServiceExternalIPs admission controller](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#denyserviceexternalips)
- [Kubernetes v1.36 deprecation announcement and migration timeline](https://kubernetes.io/blog/2026/05/14/kubernetes-v1-36-deprecation-and-removal-of-service-externalips/)
- [Kubernetes enhancement KEP-5707](https://github.com/kubernetes/enhancements/tree/master/keps/sig-network/5707-deprecate-service-externalips)
- [Kubernetes v1.36 API source: Service type and ExternalIPs](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/apis/core/types.go)

The v1.36.1 API server binary rejects the feature-gate syntax in the original
catalog. A separate Kind cluster enables `DenyServiceExternalIPs` with
`--enable-admission-plugins`. The case checks the live API server arguments,
rejection of new ExternalIPs on CREATE and UPDATE, and acceptance of an ordinary
ClusterIP Service. The versioned upstream reference documents that existing IP
values may remain or be removed. The custom policy exercises NodePort and
LoadBalancer restrictions and the synthetic approval path separately.
