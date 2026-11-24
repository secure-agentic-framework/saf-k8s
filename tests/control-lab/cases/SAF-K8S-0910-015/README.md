# SAF-K8S-0910-015 destination-side signature and digest verification

`python3 tests/control-lab/lab.py test SAF-K8S-0910-015 --docker-context desktop-linux`

Two owned Kind APIs host pinned private Distribution registries. The fixture
transfers signed inert model metadata with a fresh local key. It changes the
destination metadata under the same fixture tag while preserving the original
signature. An unchecked consumer Job reads that harmless replacement.

The scoped destination validator independently reads the registry and verifies
the manifest digest, configuration bytes, statement subject, and signature.
A Kubernetes ValidatingAdmissionPolicy holds the named Job path pending exact
verified receipt. After the original bytes are restored and verified, the named
consumer Job completes and confirms the observed manifest and metadata digests.
The still-altered digest is refused under the clean receipt.

Live registry authentication, immutable promotion and end-to-end reconciler
authorization remain deployment evidence. No model code or GPU workload runs.
