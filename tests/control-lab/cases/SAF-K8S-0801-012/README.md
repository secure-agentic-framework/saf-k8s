# SAF-K8S-0801-012 Eligibility for shared accelerator pools

This case uses one disposable Kind node labeled and tainted for one policy-approved trust group. The application workloads use a synthetic extended resource and no real accelerator. Admission rejects an ordinary subject, missing placement and direct node assignment. Two permitted CPU-only fixture Pods schedule and run on the intended node. This evidence covers the tested direct Pod path and modeled sharing pool. Actual plugin modes, physical co-location, workload-controller submitters and effective GPU isolation need deployed evidence.

## Adopter verification

1. Record the actual sharing strategy, accelerator model and topology, resource names, driver and plugin settings and permitted data and workload categories per device pool.
2. Check effective admission and scheduler paths for two approved workload canaries and a disallowed declaration. Verify actual device identities, placement labels and occupancy through authoritative node or provider telemetry.
3. Confirm a workload submitter cannot change the placement eligibility policy or directly set fields that evade the approved scheduler path. Verify concurrent workload compatibility with the approved sharing mode.
4. Retain policy revision, actual pool and device identities, observed allocation and exceptions. Recheck after updates to scheduler, labels, hardware or sharing profiles.
