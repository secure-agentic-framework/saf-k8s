# SAF-K8S-0905-045 — Sandboxed behavioral vetting and disposition

Run with the control-lab runner on a fresh disposable Kind cluster. The existing
six checks retain the deterministic three-marker fixture, reviewer separation,
reject/approve/escalate records, and the held-state readback.

The additive CPU witness loads the official llama.cpp `server-b9519` image and
the upstream `stories15M_MOE-F16.gguf` test model from the immutable upstream
revision used by SAF-K8S-0903-004. The runner verifies the 73,466,432-byte
model's SHA-256 before building an offline derived image. A restricted,
tokenless serving Pod handles one fixed `Once upon a time` request with a
four-token output cap. The evaluator Job retains only model/runtime identifiers,
token counts, stop reason, and hashes; generated text is not retained. A separate
reviewer ServiceAccount reads the immutable observation, verifies its digest,
and writes an independent `escalated` disposition bound to the runtime receipt.
The case reads back that exact disposition and confirms the candidate remains
held.

Before the model request, the case verifies the runner's bundled kindnet DaemonSet
is ready. A dedicated tokenless client with the evaluator's exact policy label first reaches
both the healthy model Pod and a case-owned inert HTTP peer. After the two
NetworkPolicies are applied, that same client still reaches the model endpoint
but cannot reach the unrelated peer. The actual evaluator Job is checked to
carry the same selector label before it makes the bounded model request. This
proves this one bundled-kindnet-enforced namespace path, not broad cluster or
production policy coverage.

This smoke request has no approved safety rubric or representative dataset, so
the real-model result is deliberately inconclusive. The witness establishes a
real bounded CPU model invocation, one isolated serving route, and a digest-bound
hold path; it does not establish that the model is safe, unsafe, or fit for
internal use. Verify actual model identity and source, representative evaluation
datasets and criteria, enforcement in the adopted CNI across every serving path,
reviewer authority, exception handling, retention, and every production
promotion path for the adopting environment.

The runtime companion is loaded from the adjacent SAF-K8S-0903-004 case and its
runtime helper and Dockerfile are checked against the reviewed SHA-256 values in
`native_model.py`. The runner supplies that sibling case. The model artifact is
fetched only by that companion at test execution time, then checked against its
pinned digest; it is not stored in this case tree. The runner must supply the
adjacent SAF-K8S-0903-004 case.

The harness also checks that the same client and peer Pods persist and that
the peer still serves its local health response after policy takes effect.
