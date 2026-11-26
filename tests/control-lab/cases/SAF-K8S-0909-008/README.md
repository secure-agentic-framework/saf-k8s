# SAF-K8S-0909-008

Run `python3 tests/control-lab/lab.py test SAF-K8S-0909-008` from the SAF-K8S repository root. The case uses disposable Kind workloads, two local persistent claims, and one synthetic mixed-classification document.

The ungoverned service exposes a fixture marker through a shared collection. The governed service authenticates projected workload identities over TLS, restricts writes to an approved identity, and validates each proposed chunk against its trusted section and destination. It stores public and confidential chunks in separate logical SQLite collections. Both readers retrieve their exact section-local vectors through the permitted route, and the opposite class returns HTTP 403.

The fixture applies a section-level strategy. Verify the actual classification authority, approved handling of overlap and missing labels, storage and identity policy, tenant boundaries, and retrieval coverage in the deployed index.

[Kubernetes Service Accounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)

## Authenticated write and approval authority

One authenticated, approved writer submits the exact fixed source/section
request. The service verifies the approved classification, section chunk and
destination before inserting the row. The corresponding reader observes that
exact public row. Requests with a mismatched classification or destination
are forbidden. The public reader cannot confer write authority by claiming a
different subject in the request. Separate reads compare the complete expected
public and confidential collections after these requests.

The case verifies that the TokenReview service account can submit TokenReviews
and is forbidden from patching the named approval ConfigMap. Independent
readback confirms the approval object is unchanged.
