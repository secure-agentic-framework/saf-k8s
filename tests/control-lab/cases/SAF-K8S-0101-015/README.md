# SAF-K8S-0101-015 — API server webhook authorizer endpoint trust controls

Run from the local lab with Kind, Docker, OpenSSL, Python and kubectl.

```sh
python3 lab.py test SAF-K8S-0101-015 --docker-context desktop-linux
```

The runner uses two fresh Kubernetes v1.36.1 Kind clusters with separate
kubeconfigs. Each API server uses the same ordered Node, RBAC, and scoped
webhook chain. The webhook handles one fixture ServiceAccount's GET of a
named ConfigMap. It uses short-lived mutual TLS on the local Kind network
and a Python container pinned by image digest. The helper has no published
host listener.

With the issuing CA in the webhook kubeconfig, the authorized GET returns
the expected marker and the backend confirms the exact SubjectAccessReview
and client certificate identity. With an unrelated CA, the identical GET
returns HTTP 500 with an x509 verification error. The backend observes the TLS
rejection and receives no matching review. An ordinary authorized namespace read succeeds in
each cluster. The runner deletes the test clusters and webhook containers.

The trusted profile briefly removes the owned webhook container. The same
request fails closed, while an unaffected authorized namespace read still
works. Recreating the trusted backend restores the original result. This check
covers an unavailable backend with the fixture's explicit failure policy.

## Adopter verification

1. Record the provider, Kubernetes version, API-server replicas, approved
   webhook owner, endpoint purpose and intended request scope. Retain the
   approver, source revision, change window and review date. Review
   third-party custody and where TLS terminates.
2. Match the effective ordered authorizer configuration with the approved
   file on every applicable replica. Check the webhook's HTTPS endpoint,
   expected DNS identity, trust bundle, client identity when mTLS is
   required, match conditions, timeout, failure policy, and cache behavior.
3. Verify an authorized comparison and its expected handling when peer
   trust or backend availability changes in an isolated environment.
   Include an unaffected client request. Review latency and certificate
   rotation with overlapping trust, affected replicas and rollback evidence.
   Keep credentials outside shared logs and review records.
4. Evaluate managed configuration where exposed and record provider
   responsibility, applicable attestations, compensating controls and
   approval. Mark unevidenced trust paths or provider settings unverified.
   Repeat the comparison and refresh approvals after endpoint, trust,
   certificate or version changes.

- [SAF-K8S original webhook authorization trust control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0101-015.md)
- [Kubernetes v1.36 AuthorizationConfiguration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authorization/)
- [Kubernetes v1.36 Webhook mode](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/webhook/)
- [Kubeadm v1.36.1 API server argument generation](https://github.com/kubernetes/kubernetes/blob/v1.36.1/cmd/kubeadm/app/phases/controlplane/manifests.go)
- [Kubernetes v1.36.1 authorization filter error handling](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go)
