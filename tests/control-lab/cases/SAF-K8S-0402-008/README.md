# SAF-K8S-0402-008 — Separate workload identities and enforce their assignment

Run from the lab checkout.

```sh
python3 lab.py test SAF-K8S-0402-008 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py`.
The disposable Kubernetes fixture runs three ordinary Pods as synthetic
training, inference and pipeline workloads. The baseline shared account has
three harmless named ConfigMap reads. Separate accounts and exact Roles each
preserve one required read. The API server independently returns the full
authorization matrix without mounting or exposing workload credentials.

A native ValidatingAdmissionPolicy applies to the selected test namespace.
The baseline could admit a wrong type and account pair. The active binding
accepts each valid pair and rejects a wrong account, missing label or unknown
label. A refused update preserves the existing Pod label and account. A
separate unselected namespace serves as the scope comparator.

## Verify the adopted identity assignments

1. Inventory workload types and owners and record the exact assigned
   ServiceAccount, namespace and intended permission for each workload.
   Govern who can assign workload classifications and scope labels or
   change the admission policy.
2. Set the appropriate labels and account on the real controllers' Pod
   templates. Observe the generated Pods for the actual Job, Deployment,
   KServe, Kubeflow, notebook or pipeline controller and repeat after a
   representative controller update.
3. Exercise the in-scope admission boundary with positive creation,
   wrong assignment, invalid classifications and controlled update
   comparisons. Verify expected exclusions independently. Record the
   policy revision, precise denial and unchanged identity where applicable.
4. Review effective permissions for the actual identities. Exercise owned
   required and unauthorized data operations at the real system boundaries.
   Verify separate assignments and approvals for any federated identity
   or external registry, model store, serving endpoint or pipeline.

[Kubernetes service accounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)
and [ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/).
