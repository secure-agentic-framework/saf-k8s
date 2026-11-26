# SAF-K8S-0903-004 — LLM context and token resource controls

The case mounts an immutable fixture into a digest-pinned Python Pod and sends
one bounded sequence of requests over the Kubernetes exec API. The driver
checks the outputs and backend counters after each operation. It demonstrates
the control with policy off and then with exact input, output, session, and
logical-clock rate limits. It also checks a distinct session and ordinary
allowed work.

The original fixture uses whitespace tokens, deterministic simulated generation,
a logical clock, and case-owned session identifiers. A second fixture adds the
actual tiktoken 0.12.0 cl100k_base encoder to an HTTP worker served inside Kind.
The host downloads the reviewed architecture-specific Python wheel and vocabulary,
checks their SHA-256 digests in tokenizer-pins.json, and builds with networking
disabled. A separate Pod uses a Kubernetes Service to verify literal BPE counts
after prompt expansion, individual HTTP chunks, and metrics. It requires an
oversized request to be refused before backend dispatch, a normal stream to
complete, and a request for five output tokens to stop at four.

The test serves fixed token IDs from a deterministic fixture on CPU. Adopters
must measure the deployed model and its tokenizer and templates, real tenant
authentication and session ownership, concurrent streaming and cancellation,
and actual KV-cache allocation and GPU limits. The logical-clock rate check
covers the original fixture.

The [FlashAttention paper](https://arxiv.org/abs/2205.14135) explains how
tiled exact attention avoids materializing the full score matrix in GPU global
memory. The [PagedAttention paper](https://arxiv.org/abs/2309.06180) explains
allocation and sharing of stored key and value blocks.
