# Verify keyless signing and a digest-bound admission decision

    python3 tests/control-lab/lab.py test SAF-K8S-0602-001 --docker-context desktop-linux

A disposable Kubernetes-issued identity signs one image through local
Fulcio, certificate transparency, Rekor and timestamp services. A separate
Cosign invocation verifies the signed image and rejects missing proof, a
wrong identity and a wrong issuer. It uses the pinned fixture trust roots
and verifies the exact signed registry reference.

The trusted test orchestrator passes the successful verification to a
separate, scoped approval identity. A native ValidatingAdmissionPolicy
requires a named immutable approval record in the fixture namespace.
Requests from the launcher are compared with the record absent and with
the exact or a different digest. The launcher lacks permission to change
the approval. The approved image then runs and reports its exact image
digest and the inert marker.

For a deployment, verify the approved identity providers, enrollment and
rotation of trust roots, signer segregation, and required signature
and transparency evidence. Independently verify the operational handoff
from a successful verifier to a protected, auditable approval and cover
each workload admission route. Include unavailable proof and failed
verification cases. The fixture uses the test orchestrator for this
handoff and measures direct Pod creation in its namespace.
