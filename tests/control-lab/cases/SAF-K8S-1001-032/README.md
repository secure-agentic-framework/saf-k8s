# SAF-K8S-1001-032 cluster-wide log collection coverage

Run from the SAF-K8S framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1001-032 --docker-context desktop-linux
```

The runner creates a Kubernetes v1.36.1 control plane and two workers. Every
node has a distinct fixture marker and a workload that emits a known stdout
line. The collector DaemonSet reads only the per-node marker mounted read-only
and the log subresources of the three named fixture Pods.

The simulated accelerator worker has a NoSchedule taint. The test observes a
collector on the control plane and ordinary worker first, then applies the
exact toleration and checks that all three nodes deliver both known values.
Generated node and Pod names remain in the raw evidence. The retained passing
checks compare roles, counts and exact markers across clusters.

Fleet-wide coverage, real device and driver telemetry, and managed-provider
log sources require separate evidence.

- [Kubernetes v1.36 DaemonSets](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/daemonset/)
- [Kubernetes v1.36 taints and tolerations](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/)
- [Kubernetes v1.36 logging architecture](https://v1-36.docs.kubernetes.io/docs/concepts/cluster-administration/logging/)
