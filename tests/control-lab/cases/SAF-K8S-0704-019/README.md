# SAF-K8S-0704-019 — Workload identity binding

From the framework checkout, run the local comparison on a fresh Kind cluster.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0704-019 --docker-context desktop-linux
```

From the lab checkout, invoke `python3 lab.py` with the same arguments.
A native admission rule links each of two owned Pods to its approved
ServiceAccount and rejects a wrong or default account. Each Pod presents
a short-lived projected token to an in-cluster TLS service. The receiving
service checks the expected audience through Kubernetes TokenReview, then
authorizes only the exact ServiceAccount subject and reads its one scoped
fixture ConfigMap. Both intended reads succeed. Wrong audience is refused
at authentication, and the other valid subject is denied without a data
read. Evidence includes status and inert marker names.

The added check binds each accepted TokenReview result to the live name and UID
of its intended Pod. A third inert Pod uses workload A's same ServiceAccount
and token audience, but its different Pod UID is refused before the marker read.
Normalized check observations contain fixed booleans; dynamic Pod names and
UIDs are confined to the bounded raw case evidence (`commands.log` and
`identity-binding-observations.json`). No bearer token is returned or logged.
This demonstrates Kubernetes bound-token attribution, not provider identity
or cloud audit evidence. The same-ServiceAccount Pod is a deliberately
Pod-specific relying-service policy example; it does not imply that all
workloads sharing a ServiceAccount should be denied.

## Verify the deployed provider integration

1. Record the managed service, cluster and workload versions, workload
   owner, effective Pod ServiceAccount or supported subject, provider
   trust or association, token audience, and intended provider principal.
   Enumerate which workloads share the same subject and record each
   approval and justification.
2. In an approved staging deployment, start the actual workload. Obtain
   provider-side evidence of the resolved identity and perform one
   approved action on a case-owned resource and a separate disallowed
   action or out-of-scope target. Exercise a workload with the wrong
   subject and, where applicable, a token with a wrong audience. Keep
   authorization decisions and request IDs. Keep credentials out of
   evidence.
3. Check the workload's effective credential chain, including node
   metadata, default credentials, injected environment or files, and
   unattended long-running sessions where applicable. Verify the approved
   configuration prevents unintended fallback from that workload.
4. Correlate the expected cloud action and denied request with provider
   audit records. Document the actual attribution granularity and an
   independent correlation method when the provider records shared
   ServiceAccount or role identity.

The local TLS relying service demonstrates Kubernetes-issued token use.
Provider exchange, provider authorization, node credential isolation and
cloud audit correlation require the provider-specific checks above.

This comparison relies on Kubernetes v1.36 bound projected tokens and
TokenReview behavior. Kubernetes v1.36 documents that TokenReview returns the
Pod name and UID for a Pod-bound token, and that the API server validates the
referenced Pod UID against the live Pod. The local Kind case is v1.36.1. See
[v1.36 Managing Service Accounts](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
and the [v1.36.1 service-account token claims implementation](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/serviceaccount/claims.go).

[Kubernetes ServiceAccounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)
and [Kubernetes TokenReview API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/).
