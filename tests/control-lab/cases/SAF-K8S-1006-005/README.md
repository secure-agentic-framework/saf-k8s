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

## Persisted Pod UPDATE comparison

This scratch variant keeps the 12 existing checks and renders a local copy of
the signed-image policy with `CREATE` and `UPDATE` operations. It creates one
case-owned compliant Pod using the approved marker-only OCI fixture and
`imagePullPolicy: Never` behind a named scheduling gate, so no image is pulled
or executed. A strategic UPDATE from one approved repository reference to a
second independently signed and attested reference, with a benign annotation,
must be accepted without changing the Pod UID. A fixed unrelated-signer image
UPDATE must be denied with the exact Kyverno policy reason; a subsequent API
read must show the same UID, generation, and full Pod spec as immediately
before the denied request. Raw API observations retain resourceVersions for
review, but the assertion does not depend on them because status updates can
be asynchronous. The owned Pod is deleted with a UID precondition and absence
is checked with a bounded wait. Raw API observations are written to
`admission-update-raw.json`; receipt observations contain normalized booleans.

This demonstrates admission handling for this one persisted fixture object. It
does not demonstrate a running workload, GPU scheduling, production policy
scope, real signer trust, or deployed admission coverage.

[Kubernetes v1.36 CEL reference](https://v1-36.docs.kubernetes.io/docs/reference/using-api/cel/), [Kyverno ImageValidatingPolicy](https://kyverno.io/docs/policy-types/image-validating-policy/)
