# Verify Kubernetes PriorityClass preemption behavior

```sh
python3 lab.py test SAF-K8S-0703-016 --docker-context desktop-linux
```

The fixture advertises one synthetic resource on a new, dedicated Kind node.
The three Pods are inert and request only small real resource amounts. A higher
priority Pod with `Never` waits while the slot is occupied. A still-higher
preempting Pod receives the slot from a lower-priority `Never` Pod despite a
PodDisruptionBudget with zero allowed disruptions.

The scheduler evidence applies to this fixture and Kubernetes version. Actual
GPU capacity, priority policy, availability and operating guarantees require
their own evidence.
