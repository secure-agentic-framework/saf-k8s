# SAF-K8S-0801-001 — DRA-backed GPU claim admission

```sh
python3 lab.py test SAF-K8S-0801-001 --docker-context desktop-linux
```

The runner creates a fresh kind Kubernetes v1.36.1 cluster. The test provisions
two case namespaces and synthetic subjects with scoped RBAC. An ordinary
subject can dry-run an ordinary ResourceClaim or ResourceClaimTemplate. Native
validation rejects `adminAccess` in the unapproved namespace, and RBAC rejects
the ordinary subject in the approved namespace. The maintenance subject's dry
runs retain `adminAccess` in the approved namespace.

The platform subject can propose the namespace approval-label changes. The
ordinary subject receives RBAC denials. Every claim, template and label-change
probe uses server dry run. The final inventory verifies the original labels
and zero persisted claims or templates. The framework retains the matching run
at `verified/SAF-K8S-0801-001.json`.

This case covers the claim-admission slice of the control. The companion
`SAF-K8S-0401-002` case checks DRA authorization tuples. Deployed GPU hardware,
driver behavior, legacy device-plugin communication and deployment hardening
remain open under `saf-lab-0801-001.2`.

- [Kubernetes v1.36 Dynamic Resource Allocation](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/dynamic-resource-allocation/)
- [Kubernetes v1.36 DRA hardening](https://v1-36.docs.kubernetes.io/docs/concepts/security/hardening-guide/dynamic-resource-allocation/)
- [Kubernetes API dry-run behavior](https://v1-36.docs.kubernetes.io/docs/reference/using-api/api-concepts/#dry-run)
