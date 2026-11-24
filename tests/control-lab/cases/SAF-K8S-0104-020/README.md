# SAF-K8S-0104-020 — Kubernetes supported version window compliance

The case evaluates a dated snapshot of upstream minor-release schedules and
patch listings. With the check disabled, the end-of-life case goes unevaluated.
With the check enabled, the same version is rejected on its end-of-life date.
Other fixtures cover the first release date, limited maintenance, an older
patch in an active series, and a patch outside the recorded snapshot.

The runner reads the actual API server and kubelet versions from disposable
kind and evaluates them against the reference date. The decision establishes
eligibility for upstream branch support as of that reference. Use current
upstream and provider schedules for real deployments. Patch currency and
completed upgrade evidence remain separate.

```sh
python3 lab.py test SAF-K8S-0104-020 --docker-context desktop-linux
```

From the framework checkout use `python3 tests/control-lab/lab.py` with the
same arguments.

- [Pinned SAF-K8S control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0104-020.md)
- [Kubernetes patch release support periods](https://kubernetes.io/releases/patch-releases/)
- [Kubernetes release history](https://kubernetes.io/releases/)

The by-ID test inventories the API server, control-plane kubelet and worker
kubelet on disposable two-node Kind. A separate synthetic provider schedule
exercises service-specific build and role matching, distinct extended support
entitlements, exclusive end dates, and stale, missing or malformed evidence. Unknown
managed builds remain unverified even when an upstream lookup would pass.

## Verify your implementation

1. Record the API server versions and every node pool and kubelet version.
   For managed infrastructure also retain the service, release channel or
   tier, support entitlement, regional availability where relevant, and
   the build or node image from the provider's authoritative inventory.
   Track provider-managed and self-managed responsibilities.
2. Match each component to the applicable dated support record. Use the
   provider lifecycle and effective tier for covered components, and the
   project's authoritative release schedule for upstream components you
   operate. Record the applicable boundary, supported patch coverage,
   evidence freshness, and the basis for any extended support decision.
3. Review control plane and node outcomes independently. An unsupported
   worker is still an actionable finding when the API server is supported.
   Escalate missing, stale, ambiguous, or unrecognized version information.
   Track patch currency, supported skew and completed upgrade proof
   separately from support-window eligibility.
4. Retain the observed versions, timestamp and availability of the
   lifecycle source, component decisions, upcoming support deadlines,
   approved exceptions and completion evidence. For an in-scope AI
   system, feed relevant version and update requirements into its
   technical documentation, where applicable.

- [Amazon EKS Kubernetes lifecycle](https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html)
- [GKE release schedule](https://docs.cloud.google.com/kubernetes-engine/docs/release-schedule)
- [AKS Kubernetes version support](https://learn.microsoft.com/en-us/azure/aks/supported-kubernetes-versions)
- [Regulation (EU) 2024/1689, Annex IV](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng/pdf)
