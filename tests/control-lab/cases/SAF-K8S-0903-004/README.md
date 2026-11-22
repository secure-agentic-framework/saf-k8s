# SAF-K8S-0903-004 — LLM context and token resource controls

The case mounts an immutable fixture into a digest-pinned Python Pod and sends
one bounded sequence of requests over the Kubernetes exec API. The driver
checks the outputs and backend counters after each operation. It demonstrates
the control with policy off and then with exact input, output, session, and
logical-clock rate limits. It also checks a distinct session and ordinary
allowed work.

The fixture uses whitespace tokens, deterministic simulated generation, a
logical clock, and case-owned session identifiers. Production tokenizer and
prompt-template behavior, authenticated session ownership, concurrent or
streaming generation, and GPU and KV cache use require separate evidence.

The [FlashAttention paper](https://arxiv.org/abs/2205.14135) explains how
tiled exact attention avoids materializing the full score matrix in GPU global
memory. The [PagedAttention paper](https://arxiv.org/abs/2309.06180) explains
allocation and sharing of stored key and value blocks.
