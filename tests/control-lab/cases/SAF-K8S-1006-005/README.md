# SAF-K8S-1006-005 combined AI workload admission

From the framework checkout, run with local Docker, Kind, Helm and kubectl.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1006-005 --docker-context desktop-linux
```

The test reuses the owned registry and inert OCI signing fixture from
SAF-K8S-0605-002. It submits server-side dry-runs before and after enrolling
the namespace in the Kyverno provenance and native Kubernetes admission
policies. It separately checks image signing and attestation, the quantity
of the named GPU extended resource, the required security-context fields,
and allowed classification labels. The fixture includes a compliant request
and an out-of-scope comparison.

The selected signer, quantity limit and class values are synthetic. Deployed
provenance, GPU allocation and broader policy coverage require their own
evidence.

[Kubernetes v1.36 CEL reference](https://v1-36.docs.kubernetes.io/docs/reference/using-api/cel/), [Kyverno ImageValidatingPolicy](https://kyverno.io/docs/policy-types/image-validating-policy/)
