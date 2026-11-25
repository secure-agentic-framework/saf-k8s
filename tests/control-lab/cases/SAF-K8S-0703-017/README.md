# Verify PriorityClass admission by namespace

```sh
python3 lab.py test SAF-K8S-0703-017 --docker-context desktop-linux
```

Two fixture service accounts can submit within their own namespaces. Native
Priority admission resolves existing classes while class-object permissions are
controlled separately. A validating admission policy then requires the one
approved class in each namespace. It rejects both an invalid direct submission
and an invalid Pod created by a Deployment controller. The approved raised
priority runs an inert Pod in the reserved namespace.

Review the actual deployed roles, class inventory, template and controller
entry points, scheduling and GPU policy separately.

## Adopter verification

1. Inventory PriorityClass objects, values, global defaults, owners, and distinct object-management grants. Confirm class-object write access is separately reviewed from Pod submission.
2. Inventory every production submission route: direct Pods, Deployment/Job templates, custom controllers, operators, admission webhooks, and namespaces. Identify the exact allowed class for each identity/workload tier.
3. Verify admission checks the effective Pod field for both direct and controller-created Pods. Test missing, unauthorized, and allowed classes without scheduling disruptive workload demand.
4. Reconcile real GPU placement and availability policies with the allowlist. Retain policy version, namespace enrollment, and exception evidence. The case does not establish deployed cluster inventory or GPU policy.
