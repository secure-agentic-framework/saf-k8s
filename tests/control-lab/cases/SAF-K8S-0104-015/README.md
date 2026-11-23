# SAF-K8S-0104-015 retaining benchmark evidence

Run `python3 tests/control-lab/lab.py test SAF-K8S-0104-015 --docker-context desktop-linux`
from the framework root or invoke `lab.py` in the lab checkout.

Two explicitly synthetic reports exercise evidence retention and trends
on a disposable Kubernetes v1.36.1 cluster. A mutable latest-only
ConfigMap loses the prior report. A case-owned PVC retains both byte
streams and their manifest after the collector Job and Pods are deleted.
Two successive reader Jobs check the stored digests and contents. The
comparison uses bytes read back from the retained archive to report one
regression and one sustained passing check over the two fixture dates.

The case uses a local node-backed PV. Its archive lasts for the
disposable test. Deployed evidence access, retention windows, durability,
and posture reporting over actual assessments remain separate.

- [Kubernetes persistent volumes and Retain policy](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/)
- [CIS Kubernetes Benchmarks](https://www.cisecurity.org/benchmark/kubernetes)
- [Aqua kube-bench](https://github.com/aquasecurity/kube-bench/tree/v0.16.0)
