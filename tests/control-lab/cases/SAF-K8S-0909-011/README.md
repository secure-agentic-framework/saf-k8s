# SAF-K8S-0909-011

Run `python3 tests/control-lab/lab.py test SAF-K8S-0909-011` from the SAF-K8S repository root. The local case loads fixed retrieved candidates and a separate approval record. It checks the exact source, version and digest, measures relevance using a documented token-overlap score, and forwards the approved top result. A separate in-cluster consumer records actual delivery or its absence.

The fixture covers a small deterministic corpus and one eligibility rule. Verify source and metadata custody, score calibration, alternate paths, and end-to-end prompt assembly and audit in the deployed system.


## Measured ranking and approval metadata

Two eligible candidates have different token-overlap scores. The higher-scoring
candidate sorts later by ID. The independent consumer must receive its exact
identifier and content digest.

The retrieval ServiceAccount can read the named approval ConfigMap through the
Kubernetes API and receives an authorization refusal for a metadata patch. An
independent read confirms the complete object is unchanged. The harness uses
API impersonation for those decisions. The retrieval Pod uses the immutable
volume projection and disables automatic token mounting.

For an adopted deployment, measure relevance on the approved corpus and scoring
model. Verify the actual authority for source metadata, route selection and
downstream context assembly and retain decision and delivery evidence.
