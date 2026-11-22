# SAF-K8S-1001-031 tenant and workload context

Run from the SAF-K8S framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1001-031 --docker-context desktop-linux
```

## Checks

The runnable case uses five case-owned fixture Pods in two synthetic namespaces.
Each app container writes its fixture JSON line to a shared emptyDir; its Fluent
Bit sidecar tails that file, enriches it from the actual Pod object through the
Kubernetes API, then sends JSON Lines over HTTP to a fixture-only receiver. The
collector receives only a namespace-local Role granting `get` on Pods. It has
no hostPath mounts, privileged mode, host networking, or write access to the
Kubernetes API. The receiver has no Kubernetes credentials.

The event payloads include only synthetic event IDs and markers. Tenant and
workload values are exclusively Kubernetes Pod labels; source identity is
expected from the Kubernetes filter's namespace, Pod, and container metadata.
The case compares exact receiver-side search results for each tenant and each
tenant/workload pair, checks no cross-tenant events or duplicate IDs, and
requires the intentionally unlabeled fixture record to be detected as missing
tenant context.

The JSON fixtures and source review are retained beside the case. The receiver
is ephemeral and case-owned. No real tenant content, unrelated workload logs,
production endpoint, credentials, or external destination are involved.

## Review boundary

The pinned control excludes initial collection and routing. This case uses a
fixture transport pipeline only to verify that enriched context reaches the
receiver intact. A pass would show this one Fluent Bit configuration and these
synthetic Kubernetes objects behave as asserted. It would not prove production
SIEM segregation/authorization, label governance, durable retention, every AI
log class, or production rollout.

The retained result includes the exact event IDs and tenant query membership
observed with Fluent Bit 5.1.2 on Kubernetes v1.36.1. See
[`source-review.md`](source-review.md) for the catalog revision and source review.
