# SAF-K8S-0202-011 MAC declaration and runtime availability

A native admission policy requires one named AppArmor profile and rejects conflicting container overrides. Kubernetes can admit the declaration even though the selected node cannot load or apply it. The test checks that the workload never starts with that unavailable profile and confirms a separate public workload can run. Actual enforcement of a loaded AppArmor or SELinux policy requires supported node evidence.
