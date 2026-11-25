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

## Adopter verification

1. Inventory deployed PriorityClasses, values, global defaults, `preemptionPolicy`, allowed submitters, and workloads in each tier. Identify protected and non-preemptible tiers.
2. For each production GPU-backed tier, verify actual accelerator requests, capacity, placement, replicas, and service health under expected contention. Include disruption budgets and recovery behavior.
3. Exercise only an approved bounded contention scenario. Observe the scheduler's selected victim and resulting inference availability, then verify recovery and return to normal capacity.
4. Record exceptions and the service availability objective. The synthetic slot proves scheduler priority semantics, not GPU capacity or production failover.
