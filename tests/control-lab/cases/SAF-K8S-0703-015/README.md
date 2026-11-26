# SAF-K8S-0703-015 adopter exercise

From the framework checkout, run the disposable queue recovery test.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0703-015 --docker-context desktop-linux
```

From the lab checkout, invoke `python3 lab.py` with the same arguments.

The retained reference receipt contains **4/4 checks** on Kubernetes v1.36.1 with Kueue v0.20.6. It verifies one finite CPU Job queued with zero quota, admission after quota restoration, a controlled synthetic dependency failure, then completion of the identical queued Job after repair. This is evidence for that fixture only; it does not establish real GPU faults, provider autoscaling, recurring production drills, or service-level recovery.

1. Before scheduling a drill, name the in-scope cluster, GPU pool and queue, workload owner, approved fault scenario, operator/rollback authority, maintenance window, maximum duration and capacity, service availability and recovery objectives, monitoring contacts, and cleanup/stop conditions. Confirm the scenario cannot affect unrelated tenants or production workloads.
2. Record the current state: GPU/node inventory and health, queue and quota configuration, workload replicas and service health, autoscaling limits, PriorityClass/preemption behavior, disruption budgets, dependency health, and the relevant recovery runbook. Preserve timestamps and immutable object/provider identifiers.
3. In an isolated approved environment, exercise one bounded failure at a time. Start with queue admission/quota behavior, then use a separately approved hardware or provider fault only if the platform offers an isolated test mechanism and rollback. Observe queue wait/admission, workload readiness, service-level indicators, fault detection, operator actions, restoration and recovery time against the predeclared objectives. Stop on any guardrail breach.
4. Reconcile actual outcomes with the runbook and objectives; record deviations, corrective actions, owner and due date, and evidence of closure. A successful local fixture run is not evidence that the production plan was tested.
5. Use the other retained controls as separate evidence inputs where applicable: SAF-K8S-0703-002 has paired checks for bounded Deployment and StatefulSet eviction and PDB behavior; SAF-K8S-0703-014 has 3 checks for a local CPU HPA replica cap; SAF-K8S-0703-016 has 3 checks for PriorityClass preemption using one synthetic extended-resource slot. These cases are separate fixtures and do not prove GPU device failure, provider autoscaling, or production availability for 0703-015.
6. Retain the approved drill plan, change/authorization record, before/after health and queue evidence, monitoring and alert delivery, operator timeline, objective comparison, cleanup record, after-action findings and corrective-action closure. Keep provider billing/capacity records and GPU vendor/device evidence separate and identify their actual source.

The adopted examples can support an approved contingency exercise and
cyber-resilience design objective when the organization records the scope,
objectives, evidence, review and corrective actions. Scope the exercise
to the actual deployed queue and workload versions.

[Run Kubernetes Jobs with Kueue](https://kueue.sigs.k8s.io/v0.20/docs/tasks/run/jobs/),
[Kubernetes workload disruptions](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/disruptions/),
and [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).
