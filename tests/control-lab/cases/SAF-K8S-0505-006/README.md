# SAF-K8S-0505-006 API server management boundary

The case starts a Kind cluster with the normal loopback administration
path and attaches two distinct fixture-owned internal Docker networks.
Both clients initially complete verified TLS with the same API server
and receive its Kubernetes version. A firewall scoped to the alternate
interface and API listener drops its subsequent TCP attempts. The firewall
packet counter confirms the traffic reached the node. The management
client still verifies the API response. Both fixture networks are removed.

The API listener uses the self-managed Kind fixture's configured port.
Cloud provider endpoint, DNS, IPv6, and production paths require separate
tests in the actual network topology.

[Kubernetes API server](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
· [GKE network isolation](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/latest/network-isolation)
· [Amazon EKS API endpoint](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html)
· [AKS authorized IP ranges](https://learn.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges)
