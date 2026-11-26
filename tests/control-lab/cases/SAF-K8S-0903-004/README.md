# SAF-K8S-0903-004 — LLM context window and token resource controls

This case combines two disposable Kind fixtures.

The original in-process fixture compares an unguarded fake generator with a guarded one. It counts whitespace-separated tokens, applies input and request/session output caps, and uses a logical clock for its synthetic rate check. Session identifiers are fixed fixture strings, not authenticated identities.

A second fixture builds a digest-pinned Python image with upstream tiktoken 0.12.0 and the SHA-pinned cl100k_base vocabulary. A separate client reaches the BPE worker through a Kubernetes Service. The existing five-request guarded HTTP sequence exercises fixed prompt expansion, BPE counts, pre-dispatch input rejection, bounded streams of synthetic token IDs, and backend counters. An additive bounded comparison sends the same fixed oversized prompt to a second instance of the same worker with only the input guard disabled.

## Evidence boundary

Both HTTP instances emit finite, fixed token IDs and do not call a language model or an actual inference serving framework. The guard comparison changes only the fixture input-limit Boolean; it does not validate another serving control. The tests do not authenticate caller or session identity, exercise concurrent generation, verify every production route or replica, or configure and measure a real KV cache or GPU memory budget.

The Pod manifests declare CPU and memory requests and limits. The earlier receipt predates the additive observation below and did not inspect effective cgroup bounds. Those declarations and the new container-bound observation are not proof of model memory safety or production capacity.

The existing 16 behavioral checks show behavior of these bounded fixtures. Adopters still need evidence from their deployed serving framework, complete tokenizer/template and routes; authenticated identity and session lifecycle; concurrent streaming/cancellation and effective budgets; actual cache and device allocations; and operational resource monitoring.

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


## Additive serving-container cgroup observation

A read-only probe runs inside the guarded serving Pod and reads the serving process's own cgroup membership and CPU/memory limit files. It reports the tightest finite CPU quota and memory ceiling visible through the cgroup hierarchy, then compares them with the guarded container's declared limits from the Pod specification. A missing bound, probe failure, or mismatch fails a green safeguard check; it does not change the existing 16 checks. The evidence is limited to observed container CPU and memory bounds. It does not measure CPU behavior under load, memory pressure or actual model allocation, GPU limits, or KV/cache limits.

The CPU serving check adds the official llama.cpp b9519 server and a 73.5 MB
upstream Stories test model. The runner selects the reviewed ARM64 or AMD64
manifest, fetches the fixed model on the host, verifies its size and SHA-256,
and builds the image without a network connection. The model directory is
searchable and its model file is read-only for the nonroot server. A separate
tokenless Pod checks native readiness, the single expected model alias, exact
tokenizer IDs for a fixed prompt, and actual generated token counts. This test
uses CPU inference and checks the stop reason at the four-token budget.

See the [upstream llama.cpp server documentation](https://github.com/ggml-org/llama.cpp/blob/b9519/tools/server/README.md)
and [pinned model revision](https://huggingface.co/ggml-org/stories15M_MOE/commit/b6dd737497465570b5f5e962dbc9d9454ed1e0eb).

The disposable runner owns the fixture Pods and tears down their Kind cluster
after evidence capture.
