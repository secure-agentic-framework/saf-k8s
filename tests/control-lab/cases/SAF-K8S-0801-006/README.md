# SAF-K8S-0801-006 local demonstration

The case tests a release gate in actual Kubernetes admission using synthetic allocation, transition and attestation records. It observes denial during quarantine, a permitted CPU Pod after explicit review, and denial after the record becomes stale. It never reads device memory, calls a reset, or observes any hardware sanitization.
