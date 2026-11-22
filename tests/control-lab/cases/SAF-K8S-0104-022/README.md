# SAF-K8S-0104-022 — Non-default feature gate inventory

The case compares two disposable Kubernetes v1.36.1 clusters. The stock API
server reports the disabled Alpha gate `TaintTolerationComparisonOperators`.
The configured API server reports it enabled. The evaluator compares both
effective observations with the tagged source default and classifies the
enabled state as a non-default entry. The test separately verifies the
actual API server command line and the matching process metric.

The demonstration covers one gate on one component. Deployed inventory needs
the applicable versioned defaults, effective state and explicit configuration,
with coverage across all control-plane and node components and applicable
provider settings. Production ownership, approval and upgrade review require
their own evidence.

```sh
python3 lab.py test SAF-K8S-0104-022 --docker-context desktop-linux
```

From the framework checkout use `python3 tests/control-lab/lab.py` with the
same arguments.

- [Kubernetes v1.36 feature gates](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/)
- [v1.36.1 feature gate defaults](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/features/kube_features.go)
