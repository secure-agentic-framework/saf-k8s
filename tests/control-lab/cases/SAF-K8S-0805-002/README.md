# SAF-K8S-0805-002 synthetic DRA comparator candidate

This scratch candidate is an additive copy of the exact 3-check case from the current published lab source. It preserves all three original assertions and adds one grouped native-DRA comparison.

The added check creates a case-owned Kubernetes v1 `DeviceClass`, `ResourceSlice`, `ResourceClaim`, and Pod on the same disposable v1.36.1 Kind node. The scheduler must populate `ResourceClaim.status.allocation`; the checker independently reads the claim, Pod, and source ResourceSlice, and requires the exact Pod UID in the claim's `status.reservedFor`. It then deletes only that Pod and claim and recreates the same names. The new objects must have distinct UIDs and the new scheduler allocation/reservation must bind to the replacement Pod UID. The checker never writes DRA status.

The ResourceSlice is inert synthetic metadata. There is no DRA driver, kubelet device preparation, accelerator hardware, provider telemetry, or physical allocation evidence. The added result is one stable grouped predicate; the case has four checks total. The result summary includes only booleans and the synthetic classification; the separate raw attachment contains only the case-owned DRA objects' public metadata needed to diagnose the join. Exact object names are cleaned in a `finally` path.

Review-only checks performed: Python AST parsing and source inspection. No Kind, Kubernetes, Docker, or live tests were run. This file is not integrated into a tracked case; the parent must review and pair-replay a copied candidate before publication.
