# SAF-K8S-0501-001 — Namespace default-deny ingress and egress

```sh
python3 lab.py test SAF-K8S-0501-001 --docker-context desktop-linux
```

One client and two healthy HTTP Pods run under bundled kindnet in a synthetic
namespace. With no NetworkPolicy, the client retrieves each listener's exact
marker. An ingress-only isolation phase blocks the unapproved listener while
egress is unrestricted. The original path works again when ingress is explicitly
allowed, then egress-only isolation blocks it. The final empty-selector policy
isolates both directions and an explicit TCP/8080 route preserves the approved
listener. Both listeners remain healthy during the final denial.

A NetworkPolicy-capable plugin supplies this dataplane enforcement. Generating
a separate NetworkPolicy at namespace onboarding calls for an actual resource
generator or GitOps reconciler. Admission mutation changes the submitted
object. Verify generation, authorization, reconciliation, deployment-specific
traffic and the required allow paths for system namespaces separately.

[Kubernetes NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) ·
[Gatekeeper mutation](https://open-policy-agent.github.io/gatekeeper/website/docs/v3.16.x/mutation/) ·
[Kyverno generation](https://release-1-18-0.kyverno.io/docs/policy-types/cluster-policy/generate/)
