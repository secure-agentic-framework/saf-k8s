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

This smoke request has no approved safety rubric or representative dataset, so
the real-model result is deliberately inconclusive. The witness establishes a
real bounded CPU model invocation and a digest-bound hold path; it does not
establish that the model is safe, unsafe, or fit for internal use. Verify actual
model identity and source, representative evaluation datasets and criteria,
sandbox and NetworkPolicy enforcement, reviewer authority, exception handling,
retention, and every production promotion path for the adopting environment.

The runtime companion is loaded from the adjacent SAF-K8S-0903-004 case and its
runtime helper and Dockerfile are checked against the reviewed SHA-256 values in
`native_model.py`. The runner supplies that sibling case. The model artifact is
fetched only by that companion at test execution time, then checked against its
pinned digest; it is not stored in this case tree.
