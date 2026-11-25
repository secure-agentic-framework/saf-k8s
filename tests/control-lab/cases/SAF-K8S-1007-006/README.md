# SAF-K8S-1007-006 — Secure AI workload decommissioning

Run from the control lab root on a disposable local Docker context:

```sh
python3 lab.py test SAF-K8S-1007-006 --docker-context desktop-linux
```

The retained lab run and independent framework replay passed five checks on
fresh Kind v1.36.1 clusters. The control lab runner pins its Kind node image by digest; the only
workload image is the official `python:3.13-slim` image pinned in `case.py` by digest.
The mock Pod runs a local sleep command, has no service-account token mount, and makes
no network requests. Its Secret object is empty; no credential values are generated,
read, printed, or archived.

## Observable sequence

1. Create one synthetic workload Pod and named support records in `saf-test`: an inert
   ConfigMap, empty Secret, ServiceAccount, namespaced Role and RoleBinding, NetworkPolicy,
   GPU-named ResourceQuota, an unbound `Retain` CSI PV record with a reserved example
   driver, and a synthetic registry-shaped CRD/custom resource. A separate comparator
   ServiceAccount gets read access to a different marker ConfigMap.
2. Delete the mock workload Pod only. The **red** check independently observes that the
   Pod is gone while every other listed target object remains and Kubernetes still
   authorizes the retired ServiceAccount's exact named ConfigMap read. It also requires
   the comparator access to be initially usable as a fixture sanity check.
3. Delete the target RoleBinding through the Kubernetes API and query native RBAC with
   `kubectl auth can-i`. The **green** check requires a denial and absence of every
   exact-name target object, including the PV, CRD, and custom resource.
4. The first **positive** check requires the unrelated comparator grant and marker to
   remain present and authorized. The case then deletes those comparator objects and
   verifies that all exact names owned by this case are absent.

The reported evidence consists of phase assertions and booleans/counts. No Secret data,
token, external identity, provider credential, request body, or arbitrary cluster object
content is included. All created Kubernetes objects use case-specific names and labels;
cleanup uses those exact names, and the cluster runner removes the disposable cluster.

## Coverage and limits

This exercises Kubernetes API object inventory and removal, removal of a namespaced RBAC
grant, a minimal mock workload, Secret object deletion without secret data, NetworkPolicy
and ResourceQuota deletion, and removal of inert CRD/custom-resource metadata. The
unbound CSI PV uses a reserved example driver and a synthetic handle; it never contacts a
storage provider. The quota uses a synthetic extended-resource name and proves nothing
about a GPU device or provider reservation. The registry-shaped CRD is only an inert
Kubernetes record, not an external model registry. External identity revocation is not
represented. These boundaries are also recorded in `fixtures/scope-boundaries.json`.

Deleting the PV API record does not show that backing data was erased. Kubernetes
documents that a PV with `Retain` leaves the external storage asset for manual cleanup.
Likewise, this does not verify provider-specific GPU release, external registry artifact
deletion, shared-secret rotation, real identity revocation, application-level deletion
or retention decisions, production inventory completeness, external custom controllers,
or operational approval/audit procedures. The case has no custom finalizer, so it does
not claim to validate arbitrary controller finalizer completion.

The fixture is intentionally restricted to synthetic defensive metadata, reserved
`example.com`/`example` values, and mock workload objects. It does not access external
feeds, registry services, identity providers, storage, GPUs, or other targets.

## Primary sources

- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/) — RoleBindings grant a referenced Role to namespaced subjects, including ServiceAccounts.
- [Kubernetes v1.36 authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authorization/) — `kubectl auth can-i` queries the authorization layer.
- [Kubernetes v1.36 Secrets](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/secret/) — Secret data is encoded, not inherently confidential; this fixture therefore contains no data.
- [Kubernetes v1.36 Persistent Volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/#retain) — `Retain` does not delete the associated external storage asset.
- [Kubernetes v1.36 Resource Quotas](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/#quota-for-extended-resources) — extended-resource quota syntax; this case uses a reserved synthetic resource name only.
- [Kubernetes v1.36 CustomResourceDefinitions](https://v1-36.docs.kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/) — custom resource and CRD lifecycle/finalizer semantics.
- [Python official image](https://hub.docker.com/_/python) — upstream image reference; `case.py` pins the selected image by digest.

The test submits each deletion with a Kubernetes UID precondition. An independent
wrong-UID request must fail, and the live marker reads verify the accepted and
revoked RBAC paths against the still-existing objects.

## Synthetic custom resource finalizer

A second owned custom resource has an explicit fixture finalizer. The
UID-preconditioned delete sets the deletion timestamp while leaving that
same object present. A JSON Patch verifies the UID, resource version and
finalizer list before removing only the fixture finalizer. The object
then disappears. Adopters verify the real owner's completion criteria
before approving finalizer removal.

## Adopter verification for timed deletion

Inventory the actual storage copies, snapshots, registries, caches, credentials,
device grants and provider reservations used by the workload. For any applicable
Article 4a processing, record the approved deletion trigger and deadline for
each covered data copy. Reconcile native Kubernetes object removal with actual
backend erasure, revocation and provider-acknowledged cleanup. Preserve the
scope, owner, exception and completion record without recording sensitive data.

The mapping is conditional on an adopted procedure that completes deletion
by the earlier applicable trigger. The local test demonstrates removal of
owned synthetic Kubernetes objects. [Article 4a official text](https://eur-lex.europa.eu/eli/reg/2026/1744/oj/eng).
