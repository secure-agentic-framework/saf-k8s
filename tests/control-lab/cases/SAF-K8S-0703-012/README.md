# SAF-K8S-0703-012 — Dedicated node pools for sensitive AI workloads

```bash
python3 lab.py test SAF-K8S-0703-012 --docker-context desktop-linux
```

A fresh three-node kind cluster has separate AI and general workers. The same
AI-affine workload schedules before the dedicated-pool taint and remains pending
with the exact untolerated taint after activation. The existing placement is
preserved by NoSchedule. An AI Pod with exact product affinity and the matching
toleration schedules to the AI worker, while an ordinary Pod schedules to the
general worker.

Separately, admission policy rejects the opted-in incomplete declaration admitted
before policy, and admits one with the required selector terms and toleration.
Who may set the qualifying labels and tolerations, the actual production node
pool, accelerator capacity and driver configuration require deployment evidence.

[Kubernetes taints and tolerations](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/) ·
[Kubernetes node affinity](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/) ·
[Kubernetes admission policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)

## Adopter verification

1. Inventory actual AI and general node pools, GPU/device and driver versions,
   advertised product labels, taints, capacity, health and pool ownership.
   Preserve source and observation time for each node label and taint.
2. Identify who may create or change qualifying node labels, taints, workload
   classification labels, affinity and tolerations. Review the effective
   authorizer/admission controls and retain approval records for exceptions.
3. Reconcile deployed AI Pod templates against the exact affinity selectors
   and matching tolerations; check that non-AI workloads cannot tolerate or
   bypass the AI-only pool policy unless approved. Include all workload
   controllers and submission paths.
4. In an owned target or approved low-risk environment, test a known-allowed
   AI workload and a known-disallowed ordinary workload. Record scheduler
   decision/events, selected node labels/taints, resource availability and
   that existing protected workloads remain in place.
5. Verify real accelerator allocation, driver readiness and usable capacity
   separately from successful scheduling. Repeat coverage after pool,
   scheduler, driver, label-authority or admission changes and retain dated
   inventory, exceptions, decisions and remediation.

**Portable evidence:** current digest `9cc82b4d0ef875f27e008b42ff073701acc31feac294a2999530667cfe44a860`
matches the passed **9-check** receipt, catalog revision
`d4328fde2e235c4d4a65baf2e08f7e45cfb81217`; Beads records paired lab/framework
runs, both clusters deleted. The three-node Kind fixture checks AI/general
placement before and after a `NoSchedule` taint, matching product affinity and
toleration, and admission for complete/incomplete declarations. It provides
no GPU hardware, production pool/driver, real label authority or capacity
evidence.

## Authority over the fixture pool label

Two case-owned service accounts exercise actual Node patch authorization
through the lab administrator's Kubernetes impersonation facility. The
ordinary identity receives a denial. The operator's grant names only the
fixture AI worker. The case confirms that changing the approved label leaves
unrelated labels and node specifications intact. An affinity Pod requires the
new value and selects that worker. The fixture uses no workload credentials
outside the disposable cluster. Apply the real cluster's identity, node-label
governance and accelerator checks when adopting this control.

See [Kubernetes RBAC resource names](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources).
