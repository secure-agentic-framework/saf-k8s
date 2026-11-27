# SAF-K8S-0902-006 — Synthetic serving cache and queue bounds

Run `python3 lab.py test SAF-K8S-0902-006 --docker-context desktop-linux`.
Two fixed fixture tenants use the same public sample. An independent local
accounting endpoint records one shared entry in the unscoped comparator and
two distinct entries with scope enabled. A repeated same-tenant request
reuses its entry. Inference responses carry only a fixed result and omit
cache accounting.

One small request occupies the worker and a second occupies the single queue
slot. One additional ordinary fixture request receives 429 while occupancy
stays unchanged. When the work is released, both accepted requests return
exact fixed results and the queue drains.

These are local admission and accounting checks on a synthetic service.
Actual KV memory isolation, engine priority, authenticated production tenant
configuration, and integration with vLLM, TGI, and Triton remain separate.

- [vLLM v0.11.0 Automatic Prefix Caching](https://raw.githubusercontent.com/vllm-project/vllm/v0.11.0/docs/design/prefix_caching.md)
- [Kubernetes Services](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/service/)

## Native CPU prompt-cache witness

The existing mock tenancy and queue checks are followed by two separate CPU-only
llama.cpp b9519 Pods with the same verified tiny Stories model. A tokenless client
sends a fixed request twice to the first Pod, then sends it to a fresh Pod. The
fixture checks the pinned tokenizer output and one-token completion bound, then
compares the server's `timings.cache_n` counters. Raw evidence identifies the two
Pod UIDs and pinned image and model. The source fixture binds both sibling
`SAF-K8S-0903-004` build files by SHA-256 before reusing its image-load procedure.
The existing validation command runs both parts and needs that companion case,
Docker with BuildKit, and HTTPS access for the pinned model and image assets.

The result covers reuse in one process and an empty initial prompt cache in a
second process. Tenant mapping, concurrent request isolation, cache zeroing,
accelerator behavior, and adoption in deployed engines require separate evidence.

The same case also enables the pinned b9519 `/metrics` endpoint on the first
server and sends two fixed completions from the tokenless client. It waits for
the native `requests_processing=1, requests_deferred=0` state before submitting
the second request, observes `requests_processing=1, requests_deferred=1`, then
requires both finite completions to report their configured generated-token
counts and the two counters to return to zero. The first completion is capped
at 192 tokens and the second at 8; the witness records counts and status only,
not prompt or response text. This is one controlled one-slot defer-and-drain
observation. It does not establish queue fairness, priority, preemption,
tenant-specific scheduling, KV-memory isolation, GPU behavior, or load capacity.
