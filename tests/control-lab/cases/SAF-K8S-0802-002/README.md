# SAF-K8S-0802-002 Workload runtime selection

Two Kubernetes RuntimeClasses refer to the same standard container runtime in this disposable Kind fixture. The approved RuntimeClass and pinned workload image remain admissible and run. Admission denies the alternate RuntimeClass and the mutable image reference. The fixture uses no GPU and does not validate NVIDIA Container Toolkit, CUDA, CDI, or host-device authorization.
