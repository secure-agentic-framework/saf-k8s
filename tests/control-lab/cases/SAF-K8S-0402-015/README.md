# SAF-K8S-0402-015 — Legacy service account token Secret retirement

```sh
python3 lab.py test SAF-K8S-0402-015 --docker-context desktop-linux
```

In a fresh kind Kubernetes v1.36.1 cluster, server dry-run admits an empty
legacy-type Secret request before policy, then rejects the same request by
type after applying a namespace-scoped admission policy. The policy still
admits an Opaque fixture in a dry run. Neither request persists an object.
A type-based inventory succeeds without returning any test Secrets. The
fixture also verifies the built-in ConfigMap that records when tracking began.

Legacy token metrics report usage. Inventory by Secret type and associated
account references is a separate operation. The cleaner applies to qualifying
inactive auto-generated tokens. Explicit retirement and migration need their
own evidence for remaining Secrets, including manually provisioned ones.
The test uses inert request bodies and never creates or uses credentials.

The framework retains `verified/SAF-K8S-0402-015.json`. The primary Bead
links the original finding, revised record and open production obligations.

- [Kubernetes v1.36 service account token tracking, cleanup and migration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
- [Kubernetes v1.36 metrics reference](https://v1-36.docs.kubernetes.io/docs/reference/instrumentation/metrics/)
