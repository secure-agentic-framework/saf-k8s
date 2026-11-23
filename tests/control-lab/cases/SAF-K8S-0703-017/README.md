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
