# Verify release-evidence admission

```sh
python3 lab.py test SAF-K8S-0606-011 --docker-context desktop-linux
```

A disposable Kind cluster initially accepts an inert promotion request with a
failed check in a server-side dry run. A Kubernetes ValidatingAdmissionPolicy
then rejects failed, skipped, and missing checks. It also rejects records for
another artifact, source revision, test revision, or policy revision. A matching
record with passed checks is admitted and retrieved by its exact API identity.

The ConfigMaps and check results are fixtures. Review deployed check producers,
permissions, scan applicability, branch rules, SCM push protection, exceptions,
and the release system separately. In a deployment, govern evidence writers and
scope promotion by an exclusive resource or identity. The fixture label only
scopes the admission rule inside its disposable cluster.
