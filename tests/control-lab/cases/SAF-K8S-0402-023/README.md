# SAF-K8S-0402-023 — Kubernetes token inventory, issuance and retirement

```sh
python3 lab.py test SAF-K8S-0402-023 --docker-context desktop-linux
```

The live Kind v1.36.1 case distinguishes a linked Secret-backed token fixture from an unlinked manual token fixture. It checks exact time-bounded exceptions, then confirms that retiring the overdue fixture removes only its named Secret and causes the native API to reject that original credential. The reference uses an explicit owned link to represent legacy inventory metadata.

The API server fixture caps ordinary TokenRequests at two hours and enables compatibility extension. A direct four-hour request receives a two-hour JWT. The admission-injected projection declares 3,607 seconds and receives a JWT with an effective lifetime of 31,536,000 seconds under the tested configuration. An explicitly declared 600-second projection receives 600 seconds, authenticates before expiry and is refused after expiry while its original Pod stays present. A fresh token for the same scope authenticates afterward.

Plan for about 12 minutes plus cluster startup due to the real expiry comparison. The fixture uses the native TokenReview verifier and retains only sanitized metadata and outcome predicates. Credential bytes stay in process memory. Long-running application reload, other Kubernetes or provider configurations, and external credential exchanges require their own evidence.

## Adopter verification

1. Inventory all governed clusters, issuers, workloads and token classes. Identify the applicable lookup, maximum lifetime and extension settings and note issuer paths you cannot observe.
2. Reconcile each exception to exact identities, owner, approval, purpose, review and retirement dates. Check legacy metadata and actual linked workload references.
3. Observe both requested duration and issued validity. Trace verifier acceptance and expiry for each eligible class and record measured results without storing the credentials.
4. Verify exact retirement at the accepting service and confirm continued use by separate permitted identities. Verify exchanged credentials under their own issuer and retention policy.

- [Kubernetes v1.36 kube-apiserver arguments](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [Kubernetes v1.36.1 TokenRequest storage](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.1/pkg/registry/core/serviceaccount/storage/token.go)
- [Kubernetes v1.36 ServiceAccounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)
