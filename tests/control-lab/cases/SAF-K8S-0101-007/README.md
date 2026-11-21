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

All classification requests are sequential and bounded. The lab establishes
classification and configured capacity. Queueing under contention, tenant
fairness and actual production capacity require separate evidence.

- [Kubernetes v1.36 API Priority and Fairness](https://v1-36.docs.kubernetes.io/docs/concepts/cluster-administration/flow-control/)
- [Kubernetes v1.36 API server options](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
