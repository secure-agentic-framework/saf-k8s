# SAF-K8S-0101-007 — API Priority and Fairness

```sh
python3 lab.py test SAF-K8S-0101-007
```

The disposable v1.36.1 API server serves the stable flow-control API. The
test checks the two configured in-flight request flags on the live server.
Kubernetes uses their sum as the APF concurrency budget and separate
mutating and non-mutating limits when APF is disabled.

Before a dedicated configuration is applied, an ordinary request from a
synthetic service account uses the built-in workload-low priority. Applying
a narrowly matched FlowSchema and Limited priority moves the same request
to its dedicated priority. The ordinary administrator and scheduler lease
requests keep their original classifications. The test resolves response
headers to live object names and discards verbose client output.

The dedicated priority has a bounded Queue response. The case compares passive
API server metrics before and after one ordinary request. The dedicated seat
limit appears, the dispatch counter increments once, and the wait histogram
gets one executed-request sample. A wait sample can represent immediate
dispatch. This case verifies classification, configured capacity, and the
monitoring signals with sequential requests.

## Adopter evidence

1. Pin the Kubernetes or managed service release, control-plane replicas,
   applicable defaults and customer/provider responsibilities. Collect
   `FlowSchema` and `PriorityLevelConfiguration` objects through an approved
   read-only export, including APF conditions. Review their order, subject and
   resource or URL matches, distinguishers, nominal shares, borrowing,
   lending, and queue or reject settings. For self-managed servers, retain
   both effective in-flight flags per API replica. Where the service owns
   those settings, retain provider evidence and mark undisclosed values as
   unverified.
2. Identify approved critical flows for controller leader election, node
   heartbeats, and other named controllers. Compare representative flow
   observations with the expected matching schema and priority. Record
   permitted product-specific configuration changes and their policy owner.
3. Use the approved monitoring pipeline to retain per-replica APF nominal
   limits, occupied seats, current queue depth, wait durations, and rejection
   rates by schema, priority, and reason. Treat counters as deltas or rates and
   account for restarts. During representative observed peaks, assess queue
   wait and rejections for critical flows separately from bulk work. Record
   the sampled workloads, time window and agreed targets. Evidence from an
   idle interval leaves the peak-capacity result unverified.
4. Review actual demand and isolate bulk priorities where necessary. Select
   the flow distinguisher appropriate to the matching rules. Namespace
   distinguishing applies to namespace-scoped resource requests. Rerun
   the narrow fixture after a catalog or implementation change and retain
   a reviewed policy record. Review any intentionally exempt or long-running
   request classes separately.

- [Kubernetes v1.36 API Priority and Fairness](https://v1-36.docs.kubernetes.io/docs/concepts/cluster-administration/flow-control/)
- [Kubernetes v1.36 API server options](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
