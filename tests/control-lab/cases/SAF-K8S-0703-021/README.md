# SAF-K8S-0703-021 — Accelerator resource declaration and admission

Run from the framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0703-021 --docker-context desktop-linux
```

From the lab checkout, invoke `python3 lab.py` with the same arguments.
One owned Kind node advertises two fixed synthetic accelerator slots.
Native admission restricts direct Pod submission to the selected
fixture identity and explicit resource request. One approved Pod
becomes Ready and consumes the one-unit namespace quota. The second
request is denied while advertised node capacity remains two.

Two separate in-cluster clients use their own projected ServiceAccount
credentials for actual API authentication. Only the approved identity
with the declared resource can server-dry-run the exact Job template.
The ordinary identity and absent resource declaration receive the
policy's Forbidden result. The submitted test Jobs remain absent.
The supplement also creates one suspended, approved fixture Job, binds a native
Pod policy parameter to that Job's exact API UID, then unsuspends it. The Job
controller's actual Pod CREATE must carry the controlling Job owner reference,
the approved synthetic resource request, the exact pinned inert image, and a
digest-qualified runtime image ID. It must run and complete successfully while
the namespace quota accounts for one unit. The supplemental policy retains the
approved submitter path and permits the controller path only for that exact
Job UID and the expected controller identity. This is one fixture-local
controller flow, not evidence of every controller or production policy.

Physical device allocation and isolation still require separate verification.

### VAP replacement ordering

The controller-path supplement creates the replacement `ValidatingAdmissionPolicy`
and its `Deny` binding before removing the prior Pod binding. It waits until the
new policy's `status.observedGeneration` covers `metadata.generation` and
`status.typeChecking` is present, then confirms the binding's exact policy name,
action, namespace selector, and required parameter reference. It also reads back
the immutable parameter and compares only the approved Job UID. Only after these
predicates pass does it delete the previous binding and policy. Kubernetes
documents `status.typeChecking` presence as completion of type checking; its
warnings do not change policy evaluation, while evaluation errors follow
`failurePolicy`. The actual controller-created Pod admission and completion
remain the behavioral comparison. This is confined to this test's owned
namespace and fixed Job.

## Verify the deployed accelerator path

1. Inventory actual extended-resource keys or DRA claims, supported
   device and scheduler versions, namespace quotas, and approved
   workload submission APIs. Identify owners and authorized changes.
2. Compare direct and controller-mediated workload submissions from
   approved and ordinary identities. Verify both the authenticated
   submitter decision and the controller-created Pod decision.
   Confirm the exact approved resource declaration reaches the Pod.
3. Observe effective quota accounting and actual allocation in an
   approved staging pool. Verify required device isolation and runtime
   visibility separately using an inert eligible workload.
4. Retain API and scheduler decisions, actual assigned identities,
   resource and policy versions, exceptions, quota updates and cleanup.

For a deployed controller path, capture the authenticated Job submitter,
admitted Job UID and template, actual controller identity, child Pod UID and
controlling owner UID, effective resource request, namespace quota accounting,
scheduled node, runtime image digest, and completion outcome. Keep the
controller's authorization rule and tested resource model version with this
evidence. Verify device assignment and isolation on the deployed plugin or DRA
path; the synthetic Kind resource is not hardware evidence.

[Kubernetes ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/),
[Kubernetes ResourceQuota](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/),
and [Kubernetes extended resources](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/manage-resources-containers/#extended-resources).

The case reads the owned controller manager configuration and verifies its per-controller ServiceAccount mode before using the exact named Job controller identity. See [Kubernetes RBAC roles for built-in controllers](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/#roles-for-built-in-controllers).
