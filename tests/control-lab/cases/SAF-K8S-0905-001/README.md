# SAF-K8S-0905-001 — Native admission against a system classification registry

This case models the control's two standardized lifecycle classes in an inert,
case-owned Kubernetes registry record. The cluster-scoped
`AISystemClassificationRegistry` named `saf-0905-001-classification-registry-v1`
contains two named systems and their profile assignments. A Kubernetes-native
`ValidatingAdmissionPolicy` uses that exact stored object as its parameter and
checks the AI Deployment's classification label plus registry, system, and
profile annotations against the corresponding registry entry. Workload labels
are claims: they pass only when they agree with the named record.

The case stores one fixed incomplete AI Deployment while policy is absent. It
submits the exact same request as a server-side dry-run before and after policy
installation. It also dry-runs explicit unknown-system, wrong-classification,
wrong-profile, and wrong-registry cases and requires the named policy's denial.
Afterward, it stores valid Deployments for both profiles and an unscoped benign
Deployment in the runner's established `saf-test` namespace. The workloads use
the lab's digest-pinned lightweight container fixture and zero replicas. No host
ports are used.

This checks native admission mechanics and stored Kubernetes objects. The
synthetic registry object is authoritative only inside this lab. The case does
not prove that a real organization's source of truth is access-controlled,
complete, approved, or kept current. It does not evaluate whether humans chose
the right lifecycle classification, nor whether the two assigned control
profiles actually enforce their intended protections. Those are separate
evidence questions. A production deployment also needs evidence that every AI
workload is in policy scope and that registry changes are governed.

The workspace gate requires a disposable Kind run and a fresh framework replay
before a result can be called verified. This scratch case has not been run
against Kubernetes.

## Versioned primary references

- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) describes native API-server admission, `paramKind`, named `paramRef`, `parameterNotFoundAction`, and validation actions.
- [Kubernetes v1.36 CustomResourceDefinitions](https://v1-36.docs.kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/) documents structural schemas for stored custom resources.
- [Kubernetes v1.36 CustomResourceDefinition API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/apiextensions/custom-resource-definition-v1/) documents the versioned CRD API.

## Gate status

Syntax and fixture logic can be checked without Kubernetes. Native policy type
checking, actual API persistence, denial receipts, cleanup, and the independent
framework replay remain unverified until the supervisor runs the case through
the authorized lab workflow.
