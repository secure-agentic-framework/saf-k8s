# SAF-K8S-0103-008 Controller execution and identity boundaries

A standalone fixture reconciler uses its own workload identity and updates only its public marker after permissions are narrowed. The native kube-controller-manager keeps its lease and reconciles a new Deployment after the fixture workload exits. The fixture does not use a cloud provider controller, cloud IAM or any external service. Verify deployed provider controller ownership, identity, migration and failure dependencies separately.
