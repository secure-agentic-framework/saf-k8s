# SAF-K8S-1004-005

The pod serves synthetic review records and computes the review decisions inside the cluster.
The case rejects the draft NISTIR 8269 reference, an unsupported incident/class and actor
assertion, contradictory evidence, evidence from another tenant, and stale or incomplete
records. An approved predictive-AI observation has evidence for the system and lifecycle
metadata. The actor and class stay unknown and the record remains pending human review.

NIST lists IR 8269 as a 2019 initial public draft. The final March 2025 edition is
NIST AI 100-2e2025. Its predictive and generative taxonomy and terminology inform this
case-owned review schema. Kubernetes namespace and fixture freshness fields are local
policy. Deployment, production classification, incident attribution and the complete pattern
library require separate evidence.

- [2019 NIST draft](https://csrc.nist.gov/pubs/ir/8269/ipd)
- [Final NIST AI 100-2e2025](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)

The complementary records use synthetic metadata for both the predictive and
generative branches of the final publication. The in-cluster evaluator accepts
both evidence-backed records for human review. If scoped source records disagree
on system type, the evaluator rejects the asserted concrete type and accepts an
explicit unknown with rationale for review. All inputs are abstract metadata.
Deployed detections, incident attribution, and analyst workflow need deployment
evidence.

- [NIST AI 100-2e2025, Sections 2 and 3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf)


Scope clarification for this verification copy: the five fixture fields form a case-owned review projection, not five dimensions claimed by NIST. `system_type` is a local selector for the predictive and generative branches; the other selected fields are informed by NIST AI 100-2e2025 Sections 2 and 3. The fixture does not implement the complete NIST taxonomies. The five original checks cover this local projection.


## Scoped library revision and pending review

A separate owned namespace holds a versioned synthetic library and the review
record. Kubernetes RBAC gives the impersonated case curator mutation authority
for the named records and gives the observer read authority. Native admission
uses the current library ConfigMap as its parameter. It rejects stale references
and assertions that turn the synthetic observation into an established incident
or attack classification. The allowed update keeps the exact review pending and
binds its original synthetic evidence digest to the new library revision.

The case records the exact API object UIDs and returned resource versions.
It uses authenticated lab-admin impersonation to exercise named RBAC principals.
The library contains fixture metadata. Human authority, production detection
coverage, deployed workflow, risk analysis, and the full NIST taxonomy require
adopter evidence.

- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes v1.36 Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
