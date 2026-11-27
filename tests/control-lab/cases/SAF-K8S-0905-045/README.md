# SAF-K8S-0905-045 — Sandboxed behavioral vetting and disposition

Run with the control-lab runner on a fresh disposable Kind cluster. The existing
six checks retain the deterministic three-marker fixture, reviewer separation,
reject/approve/escalate records, and the held-state readback.

The additive CPU witness loads the official llama.cpp `server-b9519` image and
the upstream `stories15M_MOE-F16.gguf` test model from the immutable upstream
revision used by SAF-K8S-0903-004. The runner verifies the 73,466,432-byte
model's SHA-256 before building an offline derived image. A hardened, tokenless serving Pod handles one fixed `Once upon a time`
request with a four-token output cap. The evaluator Job retains only model/runtime identifiers,
token counts, stop reason, and hashes; generated text is not retained. On arm64,
the evaluator also compares the exact four-token output signature for this one
fixed benign prompt to the same pinned model/runtime signature observed in two
retained 0903-004 CPU-engine raw records. This is a one-item deterministic output
regression check. It does not interpret the generated text or classify broader
safety behavior. No approved output baseline is asserted for amd64; that path
remains inconclusive. A separate reviewer ServiceAccount reads the immutable
observation, verifies its digest, and writes a disposition bound to the runtime
receipt. A matching regression remains `escalated` because one sample is not
sufficient to approve a model. A mismatch is recorded as a regression signal and
also remains `escalated`; one fixed output does not establish unsafe behavior.
The case independently reads back the decision.

Before the model request, the case verifies the runner's bundled kindnet DaemonSet
is ready. A dedicated tokenless client with the evaluator's exact policy label
first reaches both the healthy model Pod and a case-owned inert HTTP peer. After the two
NetworkPolicies are applied, that same client still reaches the model endpoint
but cannot reach the unrelated peer. The actual evaluator Job is checked to
carry the same selector label before it makes the bounded model request. This
proves this one bundled-kindnet-enforced namespace path, not broad cluster or
production policy coverage.

This one-entry regression is separate from a model-safety judgment. The witness
establishes a bounded CPU model invocation, one policy-enforced same-namespace
serving route, and a digest-bound disposition; it does not establish that the model
is safe, unsafe, or fit for internal use. Verify actual model identity and source, representative
evaluation datasets and criteria, enforcement in the adopted CNI across every
serving path, reviewer authority, exception handling, retention, and every
production promotion path for the adopting environment.

The runtime companion is loaded from the adjacent SAF-K8S-0903-004 case and its
runtime helper and Dockerfile are checked against the reviewed SHA-256 values in
`native_model.py`. The runner supplies that sibling case. The model artifact is
fetched only by that companion at test execution time, then checked against its
pinned digest; it is not stored in this case tree. The runner must supply the
adjacent SAF-K8S-0903-004 case.

The arm64 baseline is the SHA-256 of the canonical four-token sequence
observed in retained CPU-runtime receipts for SAF-K8S-0903-004. The lab and
framework receipts agree on the pinned model digest, arm64 runtime and
completion sequence. The fixture stores its expected digest only and keeps
generated text and token IDs out of the review evidence. Other architectures
remain held pending a reviewed baseline.

[Verified CPU model companion](../../verified/SAF-K8S-0903-004.json)

## Evaluation and isolation boundary

The six toy checks exercise disposition workflow using inert marker data. The additive
CPU witness does execute one pinned model request, but checks only a single fixed
output regression on arm64; it does not classify model safety or establish that
behavioral vetting detects unsafe or backdoored behavior. Evaluation criteria and
data should be selected and documented for the intended use and assessed risks. A
pass applies only to those criteria and observations; inconclusive or insufficient
coverage remains held for review.

The tested Pod controls are container hardening and one NetworkPolicy path, not a
claim of VM-grade or escape-resistant sandboxing. Kubernetes documents the default
seccomp profile as a container hardening control and identifies gVisor as an option
when stronger sandbox isolation is needed. NetworkPolicy enforcement requires a
conformant enforcing network plugin; this fixture demonstrates its one route with
the runner-bundled kindnet. Verify the isolation runtime, policy implementation,
resource boundaries and every required route in the adopting environment.

Primary guidance: [NIST AI RMF 1.0](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf),
[NIST Generative AI Profile](https://nvlpubs.nist.gov/nistpubs/AI/NIST.AI.600-1.pdf),
[Kubernetes Linux kernel security constraints](https://kubernetes.io/docs/concepts/security/linux-kernel-security-constraints/),
and [Kubernetes NetworkPolicies](https://kubernetes.io/docs/concepts/services-networking/network-policies/).
