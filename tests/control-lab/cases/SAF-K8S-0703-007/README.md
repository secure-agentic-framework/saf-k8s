# SAF-K8S-0703-007 — Fair-share admission for synthetic GPU capacity

```sh
python3 lab.py test SAF-K8S-0703-007 --docker-context desktop-linux
```

The case verifies the official Kueue v0.20.6 manifest digest, pins
the controller image and enables Fair Sharing before startup. It
uses two equal-weight ClusterQueues in the same cohort. Each has
one unit of synthetic capacity.

Two Jobs in team A reserve its nominal unit and the unused unit
from team B. With reclamation disabled, team B's request remains
pending for insufficient quota. Kueue reports two reservations,
the one borrowed unit and a positive weighted share for team A.
Enabling cohort reclamation admits the same pending request and
releases team A's borrowed reservation. Both queues end with one
admission and no fixture Pod assigned to a node.

The requested resource is an unallocated synthetic name. Hardware
allocation, production fairness over time, gang scheduling, authority
over tenant queue selection, and workload-specific coverage require
their own evidence.

- [Kueue v0.20.6 release](https://github.com/kubernetes-sigs/kueue/releases/tag/v0.20.6)
- [Kueue v0.20 ClusterQueues](https://kueue.sigs.k8s.io/v0.20/docs/concepts/cluster_queue/)
- [Kueue v0.20 Fair Sharing and preemption](https://kueue.sigs.k8s.io/v0.20/docs/concepts/preemption/)
