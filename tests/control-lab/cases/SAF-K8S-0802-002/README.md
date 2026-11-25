# SAF-K8S-0802-002 Workload runtime selection

Two Kubernetes RuntimeClasses refer to the same standard container runtime in this disposable Kind fixture. The approved RuntimeClass and pinned workload image remain admissible and run. Admission denies the alternate RuntimeClass and the mutable image reference. The fixture uses no GPU and does not validate NVIDIA Container Toolkit, CUDA, CDI, or host-device authorization.

## Adopter verification

1. Record deployed GPU toolkit, runtime and driver versions, runtime profiles, CDI specifications and the device-plugin mode. Verify compatibility and what identity can change those inputs.
2. With approved inert workloads, compare the declared and admitted RuntimeClass, approved image digest and actual assigned device and mounts. Verify the application smoke and expected refusal for a mismatched runtime or unauthorized device request.
3. Retain effective node configuration, policy version, admitted Pod spec, assignment evidence and reviewed exceptions. Recheck after toolkit, profile, driver or node image changes.
