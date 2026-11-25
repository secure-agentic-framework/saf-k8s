# SAF-K8S-0801-014 Enforcement of an accelerator sharing risk decision

The actual API enforces an inert risk decision for one operator-labeled namespace. It denies restricted submissions requesting a synthetic shared or unknown resource. The permitted dedicated declaration and a lower-risk namespace's shared declaration both create CPU-only Pods.

The scheduler accounts for two synthetic resources without reserving hardware. This test observes admission, policy scope and scheduling. Physical sharing, device guarantees and configuration-specific assessment remain separate requirements.

## Adopter verification

1. Identify data classification, workload trust tiers, actors, device and sharing modes and all applicable host, network and accelerator paths. Record the evidence and assumptions underlying the approved threat assessment.
2. Verify the exact dedicated or shared allocation approved for each class using representative inert Pods. Check admission, scheduler, node or provider allocator and effective device evidence together.
3. Confirm a restricted workload with a changed sharing mode or unknown profile receives the expected denial. Verify normal lower-tier usage remains authorized and distinct.
4. Retain threat decisions, observer and approval roles, device evidence, exceptions and review dates. Reassess after topology, assurance or threat changes.
