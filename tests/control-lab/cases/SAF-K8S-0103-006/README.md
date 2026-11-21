# SAF-K8S-0103-006 — Control-plane component profiling

This test checks kube-controller-manager and kube-scheduler on the pinned
v1.36.1 kind node. A temporary service account receives GET access for the
profiling index and health endpoints only. The node-local client sends its
credential through stdin. It requests only the standard index and health
routes, discards response bodies, and reports HTTP status. The probe relies
on the isolated node and loopback endpoint for server identity.

| Profile | Controller-manager index | Scheduler index | Authenticated health |
| --- | --- | --- | --- |
| Stock kubeadm | 200 | 200 | 200 for both |
| Profiling flags false | 404 | 404 | 200 for both |
| Scheduler component config disables profiling while its flag is true | 404 | 404 | 200 for both |

The default profile also returns Forbidden to both index requests without the
probe identity. The third profile checks the scheduler's exact configuration
file and verifies precedence with actual endpoint behavior.

For AWS-hosted EKS, Google-hosted GKE, and Azure-hosted AKS, the provider
operates the scheduler and core controllers. Record this control as
provider-managed for the hosted components. The ownership references do not
attest to a deployed profiling setting. Apply the local verification to
self-managed components and identify the operator for other arrangements.

- [Amazon EKS control plane configuration](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-configuration.html)
- [GKE cluster architecture](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/cluster-architecture)
- [Azure AKS core concepts](https://learn.microsoft.com/en-us/azure/aks/core-aks-concepts)

Other debug and access paths are outside this profiling control.

- [Kubernetes v1.36 kube-controller-manager flags](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)
- [Kubernetes v1.36 kube-scheduler flags](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-scheduler/)
- [Kubernetes v1.36 scheduler configuration](https://v1-36.docs.kubernetes.io/docs/reference/config-api/kube-scheduler-config.v1/)
