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
Physical device allocation and controller-generated Pod authorization
have their own verification.

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

[Kubernetes ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/),
[Kubernetes ResourceQuota](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/),
and [Kubernetes extended resources](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/manage-resources-containers/#extended-resources).
