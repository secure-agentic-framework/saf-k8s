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
