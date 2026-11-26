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

[Kubernetes ServiceAccounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)
and [Kubernetes TokenReview API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/).
