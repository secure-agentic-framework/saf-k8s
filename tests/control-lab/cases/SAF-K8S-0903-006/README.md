# SAF-K8S-0903-006 — bounded inference queue fixture

This scratch case deploys one digest-pinned Python serving workload in a disposable
Kind cluster. The server accepts only the fixed synthetic job IDs in
`fixtures/queue.json`. It holds dispatch on command, reports a receipt for each
submission, caps waiting depth at two, orders queued work by authorized fixture
class, and expires waiting work against a manually advanced logical clock.

The case checks the server's actual state and receipt endpoint after each action:

- **Green:** the normal standard job is executed exactly once and leaves no pending work.
- **Red:** a standard fixture principal cannot claim the priority class; at a held
  queue depth of two, another fixed job is rejected with a `queue_depth_limit` receipt.
- **Positive:** releasing held work executes the authorized priority item before
  the earlier standard item. Advancing the fixture clock expires a held job, removes
  it from pending, and records `execution_count: 0`.

There are no generated traffic streams, model artifacts, external endpoints, Service
objects, credentials, or Secret resources. The client uses `kubectl exec` to issue
fixed localhost calls to the single server process. The queue's request IDs and
principal labels are harmless test data.

## Limits

This is a queue behavior fixture, not Triton, KServe, or another production inference
server. The principal-to-class map tests authorization policy decisions but does not
authenticate the synthetic principal label. Production validation must establish
identity binding and class grants at the actual trusted ingress, verify queue limits
and timeout behavior on the deployed serving stack, and cover replicas, restart and
failover behavior, durable receipts, monitoring, and real inference semantics.
Kubernetes `PriorityClass` governs Pod scheduling and does not prove application
inference queue ordering.

The supervising reviewer should perform any live Kind/Docker run and compare the
reported check observations to the exact receipts. This scratch review did not run
the lab runner.

## Primary upstream references

- [Triton dynamic batching and queue policy](https://docs.nvidia.com/deeplearning/triton-inference-server/user-guide/docs/user_guide/batcher.html) documents per-model priority levels, queue size limits, and queue timeout policy.
- [Kubernetes Pod priority and preemption](https://kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/) describes Pod scheduling queue ordering, which is a different layer from inference request queue ordering.
- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) documents API authorization; this fixture does not claim its synthetic header-like principal labels implement Kubernetes or production authentication.
The baseline is a separate case-owned serving Pod using the same fixture with
the queue guards disabled. Its fixed jobs show the full backlog, arrival
ordering, and an expired item reaching dispatch. The guarded Pod enforces the
limit, class ordering, and expiry against the same synthetic jobs.
