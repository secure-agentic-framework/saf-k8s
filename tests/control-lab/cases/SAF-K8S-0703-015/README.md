# SAF-K8S-0703-015 — Queue admission and bounded Job recovery

```sh
python3 lab.py test SAF-K8S-0703-015 --docker-context desktop-linux
```

A 10m CPU Job waits in Kueue v0.20.6 with a zero quota and creates no Pods.
Restoring 10m of quota admits the same Workload and unsuspends the same Job.
Its owned Pod runs and reports the controlled synthetic dependency failure
with exit code 42. After the fixture dependency is restored, an identical
queued Job completes and reports the expected recovery marker.

This exercises one local quota recovery and application restart. Periodic
drills, actual accelerator failure, real saturation, PriorityClass and
disruption budget behavior, provider autoscaling and production recovery
procedures require their own evidence.

[Kueue Job integration](https://kueue.sigs.k8s.io/v0.20/docs/tasks/run/jobs/) ·
[Kueue ClusterQueue](https://kueue.sigs.k8s.io/v0.20/docs/concepts/cluster_queue/) ·
[Kubernetes Jobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/)
