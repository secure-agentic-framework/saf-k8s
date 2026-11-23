# SAF-K8S-0201-007 hard kubelet eviction threshold

Run `python3 tests/control-lab/lab.py test SAF-K8S-0201-007 --docker-context desktop-linux`
from the framework root.

The test raises the worker hard memory threshold above observed free memory while leaving positive
allocatable capacity while a small, bounded Pod is healthy. It observes the native
pressure signal and termination of that Pod before its configured grace
period. The PodDisruptionBudget permits zero voluntary disruptions before
pressure. The control plane stays ready. The original worker settings are
restored and a new ordinary Pod becomes ready.

The raised value creates a controlled condition without consuming excess
memory. Production values, physical capacity protection, storage
thresholds, managed service and GPU-specific tuning remain separate.

- [Kubernetes v1.36 node-pressure eviction](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/)
