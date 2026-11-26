# SAF-K8S-0903-004 — LLM context window and token resource controls

This case combines two disposable Kind fixtures.

The original in-process fixture compares an unguarded fake generator with a guarded one. It counts whitespace-separated tokens, applies input and request/session output caps, and uses a logical clock for its synthetic rate check. Session identifiers are fixed fixture strings, not authenticated identities.

A second fixture builds a digest-pinned Python image with upstream tiktoken 0.12.0 and the SHA-pinned cl100k_base vocabulary. A separate client reaches the BPE worker through a Kubernetes Service. Five sequential HTTP requests exercise fixed prompt expansion, BPE counts, pre-dispatch input rejection, bounded streams of synthetic token IDs, and backend counters.

## Evidence boundary

The HTTP worker exercises only its guarded configuration. It emits finite, fixed token IDs and does not call a language model or an actual inference serving framework. The tests do not authenticate caller or session identity, exercise concurrent generation, verify every production route or replica, or configure and measure a real KV cache or GPU memory budget.

The Pod manifests declare CPU and memory requests and limits. The receipt does not inspect effective cgroup files, usage, throttling, or memory pressure. Those declarations are not proof of model memory safety or production capacity.

The 14 checks show behavior of these bounded fixtures. Adopters still need evidence from their deployed serving framework, complete tokenizer/template and routes; authenticated identity and session lifecycle; concurrent streaming/cancellation and effective budgets; actual cache and device allocations; and operational resource monitoring.

The [FlashAttention paper](https://arxiv.org/abs/2205.14135) explains exact tiled attention and reduced GPU-memory traffic. The [PagedAttention paper](https://arxiv.org/abs/2309.06180) discusses serving-side KV-cache blocks, sharing, and allocation.


The streaming check first waits for an EndpointSlice that identifies the exact
Ready Pod and the expected port. A bounded TCP readiness check from the client
Pod allows the Service route to converge before the five HTTP requests begin.

The request-guard comparison starts a second case-owned Service and Pod with
the same worker, tokenizer, prompts and output limits. Only the fixture input
limit is disabled in that Pod. The identical expanded prompt is refused before
dispatch by the guarded Service and dispatched by the comparator. The comparison
client accepts only the fixture Service name and uses four bounded HTTP
exchanges with fixed inputs. Separate backend counters confirm the difference.
