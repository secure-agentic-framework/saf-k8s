# SAF-K8S-0101-007 — API Priority and Fairness

Run from the framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0101-007 --docker-context desktop-linux
```

From the lab checkout, invoke `python3 lab.py` with the same arguments.
The owned v1.36.1 API server reports its two in-flight settings and
apportions their sum among APF priorities. A narrow FlowSchema changes
classification for the fixture identity. Native kubelet and scheduler
Lease writes retain their expected critical priority classifications.

One nonroot fixture Pod uses its projected identity and verified
Kubernetes TLS. The configured identity is limited to GET on one
named ConfigMap. Each of the two comparison modes sends four fixed
requests to that single object. TLS connects before the requests
are synchronized, and the client performs no retries. The Queue
comparison observes positive executed wait and successful responses.
The Reject comparison observes a native HTTP 429 and an increase
in the corresponding priority's concurrency-limit rejection metric.
The test verifies removal of its seven fixture objects.

## Verify deployed flow isolation and capacity

1. Identify API server replicas and versions, the responsible team or
   managed service, relevant in-flight flags and effective APF defaults.
   Collect supported provider configuration where applicable.
2. Inventory governed critical and bulk flows, including Kubernetes
   controllers, Lease writes, and node traffic. Verify actual subject,
   request rule, unique priority, nominal shares and any borrowing,
   lending or exempt behavior.
3. Observe independent per-replica wait, queue depth, seat use and
   rejection by priority and reason. Compare critical and bulk
   traffic during representative expected workload conditions under
   an approved capacity procedure. The local comparison covers one
   controlled fixture priority and two four-request groups.
4. Record changes, accountable approvers, supported rollback, expected
   service thresholds, and repeated representative measurements.
   Verify applicable long-running requests and provider limits separately.

[Kubernetes API Priority and Fairness](https://v1-36.docs.kubernetes.io/docs/concepts/cluster-administration/flow-control/),
[Kubernetes API server options](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/),
and [the APF rejection evidence reference](upstream-rejection.md).
