# SAF-K8S-0903-004 — LLM context window and token resource controls

The portable case combines synthetic token-budget checks, a pinned BPE HTTP
service, and native CPU inference in disposable Kind. The synthetic comparison
covers input and output caps, fixture-session accounting and a logical-clock
rate check. The pinned tiktoken service observes expanded-prompt BPE counts,
pre-dispatch refusal and bounded streaming. The pinned llama.cpp server checks
native tokenization, output and the configured output guard.

## Evidence boundary

Twenty assertions cover the fixed fixture inputs, routes, sessions and named
resources. The cgroup observation verifies the running container's CPU and
host-memory bounds. Adopters verify authenticated identities and sessions, all
serving routes and templates, concurrency and cancellation, resource fairness,
actual cache and device limits, and operating metrics.

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

A read-only probe runs inside the guarded serving Pod and reads the serving process's own cgroup membership and CPU/memory limit files. It reports the tightest finite CPU quota and memory ceiling visible through the cgroup hierarchy, then compares them with the guarded container's declared limits from the Pod specification. A missing bound, probe failure, or mismatch fails a green safeguard check; The cgroup check is included in the paired 20-check receipt. The evidence is limited to observed container CPU and memory bounds. It does not measure CPU behavior under load, memory pressure or actual model allocation, GPU limits, or KV/cache limits.

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


## Native request output budget

The case keeps the original native model and all prior checks. It compares
one fixed five-token completion directly against the pinned CPU backend with
the same request through a local four-token guard. The guard binds only to the
existing fixture client Pod loopback. The over-budget request receives an
explicit rejection and the guard dispatch counter stays at zero. The allowed
four-token request reaches the exact same native server and produces four
tokens. The result preserves bounded counts and the exact server identity.
Verify equivalent policies on actual routes, model instances, streaming and
session paths, and independently measure cache allocation and device budgets.

In the pinned server source, an explicit task token count takes precedence
over the global default when checking the remaining generation budget.

[llama.cpp b9519 server budget source](https://github.com/ggml-org/llama.cpp/blob/b9519/tools/server/server-context.cpp#L263-L277)
