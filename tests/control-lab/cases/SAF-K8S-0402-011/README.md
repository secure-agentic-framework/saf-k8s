# SAF-K8S-0402-011 — Static credential admission and inventory

Run from the lab checkout.

```sh
python3 lab.py test SAF-K8S-0402-011 --docker-context desktop-linux
```

From the framework checkout, invoke `python3 tests/control-lab/lab.py`.
All Secrets in the disposable Kubernetes fixture are empty. The baseline
accepts explicitly declared cross-environment static credentials under two
inference profiles. The native policy refuses the same create and update
operations. The refused objects stay absent or unchanged, and an approved
local Secret persists.

An independently observed inventory renders only Secret types, names,
UIDs and classification labels across three owned namespaces. It finds the
three exact records that existed before the policy was active. The fixture
checks provenance and deletes those three objects, then verifies the
inventory clears and the unrelated local Secrets stay present.

## Verify the adopted credentials

1. Record every governed cluster, environment, workload and authentication
   path. Define how issuers and admission controllers classify credentials,
   and restrict authority to edit environment labels, credential classes and
   exceptions. Unknown classifications need review.
2. Confirm effective admission decisions on owned representative objects.
   Check the prohibited type and scope on creation and update, approved
   local credentials and authorized exception handling. Independently
   verify persisted state and the exact named rule.
3. Reconcile inventories across each approved Kubernetes context and
   provider identity store with actual workload references, secret
   importers, replication, delivery and CI configuration. Retain allowed
   metadata, scan scope, approved exceptions and corrected records. Verify
   holdover objects and independent cleanup results.
4. Exercise the authorized short-lived identity path against its actual
   receiving service. Validate issuer, audience, subject, lifetimes,
   key custody and rotation. Verify an allowed principal and an
   unauthorized comparator while keeping raw credentials out of logs.
   [SAF-K8S-0501-006 demonstrates a paired cross-cluster mTLS identity comparison](https://github.com/secure-agentic-framework/saf-k8s/blob/9fa32b38b12ea0d400313b81d6854ee1a57d1ace/tests/control-lab/cases/SAF-K8S-0501-006/README.md).

[Kubernetes Secrets](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/secret/)
and [ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/).
