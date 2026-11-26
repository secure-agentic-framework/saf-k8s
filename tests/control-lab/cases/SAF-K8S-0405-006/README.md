# SAF-K8S-0405-006 Attribute-based artifact authorization

Run by ID on fresh Kind. Projected workload credentials are verified
by Kubernetes TokenReview. The case-owned HTTPS artifact service reads
an immutable attribute registry and applies independent classification,
sensitivity and environment criteria to actual reads. Two intended
workload paths retain access to their approved artifact.

The fixture uses public bytes and temporary identities. Verify production
attribute authority, logs, registry and object-store enforcement and
all supported read paths independently.

The current four-check public receipt contains the original three attribute
read checks and one grouped version-selection comparison. The case creates two
immutable, case-owned attribute-version ConfigMaps and a mutable `current`
pointer. The HTTPS resource service uses its
own TokenReview-authorized service account to read the pointer and only the
two named immutable versions. A separate writer Pod uses its own projected
Kubernetes service-account token; namespace RBAC grants it `patch` only on
the current pointer. A second writer identity has no such grant. With version
v1 selected, the developer's actual read of the restricted fixture artifact
is denied. The unapproved writer's patch is refused and the pointer remains
v1. The authorized writer changes the pointer to pre-seeded immutable v2,
after which the actual read succeeds and the existing development read still
succeeds. The writer requests contain only a fixed version name; tokens and
API response bodies are never printed or retained. No real data, identity
provider, or external service is used.

The version switch is a Kubernetes RBAC reference mechanism, not evidence
that any organization's attribute values are approved or authoritative. For
adoption, identify the source and accountable owner for each subject, object,
action and environment attribute; document who can propose, approve, publish
and revoke each version. Verify version integrity, publisher authorization,
change/audit records, freshness and rollback. Then exercise the real
resource-side read path for approved and denied subjects/actions/objects and
verify that direct store endpoints cannot bypass it. Reconcile all stores,
model endpoints, data services and other access modes. The current two
crosswalk rows are already conditional; keep their applicability conditions
as adopter requirements rather than treating this local RBAC demonstration
as proof of external attribute governance.

- [NIST SP 800-162](https://doi.org/10.6028/NIST.SP.800-162)
- [Kubernetes service account administration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
