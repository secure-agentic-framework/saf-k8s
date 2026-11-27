# SAF-K8S-0801-006 local demonstration

The case tests a release gate in actual Kubernetes admission using synthetic allocation, transition and attestation records. It observes denial during quarantine, a permitted CPU Pod after explicit review, and denial after the record becomes stale. It never reads device memory, calls a reset, or observes any hardware sanitization.

The extended case varies the allocation and target trust independently, then
removes the approved parameter and observes the admission policy's missing-parameter
denial. A newly created, exact approval record restores the permitted admission.
The check applies to one named CPU fixture workload and one synthetic transition.
Verify device sanitization and the adopted allocation boundary separately.
