# SAF-K8S-0801-010 Accelerator request admission

This disposable Kind case checks actual Kubernetes identity and profile admission, an extended-resource namespace quota and a successfully scheduled Pod. Two units of a synthetic resource are advertised on the owned node while the namespace is restricted to one unit. The workload only runs a CPU sleep command. No accelerator, driver, device plugin, real allocation, or device isolation is exercised.

## Adopter verification

1. Inventory supported hardware and plugin versions and map each approved profile to the exact resource name and eligible node pool. Confirm the source and owner for each namespace approval.
2. Check regular and init requests, admitted Pod fields, quota configuration, scheduler result and actual device assignment for a permitted workload. Compare observations with device inventory and verify a known smoke operation.
3. Verify that an unapproved profile and a request beyond the approved ceiling receive the intended distinct denial. Confirm a normal CPU workload and a valid accelerator workload remain admitted.
4. Retain identity, resource profile, policy version and allocator evidence. Recheck after profile, hardware, driver or namespace changes.
