# SAF-K8S-0505-003 internal Service endpoint protection

This case uses the upstream Kubernetes Service API and pinned Cilium. It
compares an ordinary ClusterIP, a selector-backed headless Service and the
Pod address for the same owned HTTP endpoint. Both clients reach it before
policy. After the endpoint NetworkPolicy only the selected client reaches
the marker. The unselected client's TCP connection times out on all three
paths, and the selected client's requests still succeed.

The admission check verifies the Kubernetes default and then requires that
type in one namespace. It compares server-side dry-run results for an
explicit NodePort before and after the rule, plus an allowed defaulted
ClusterIP submission. Production inventory and exception policy are tracked
separately.

[Kubernetes Services](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/service/)
· [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
