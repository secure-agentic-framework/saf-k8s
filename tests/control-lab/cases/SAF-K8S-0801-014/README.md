# SAF-K8S-0801-014 Enforcement of an accelerator sharing risk decision

The actual API enforces an inert risk decision for one operator-labeled namespace. It denies restricted submissions requesting a synthetic shared or unknown resource. The permitted dedicated declaration and a lower-risk namespace's shared declaration both create CPU-only Pods.

The scheduler accounts for two synthetic resources without reserving hardware. This test observes admission, policy scope and scheduling. Physical sharing, device guarantees and configuration-specific assessment remain separate requirements.
