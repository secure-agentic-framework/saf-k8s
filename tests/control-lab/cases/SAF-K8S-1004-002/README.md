# SAF-K8S-1004-002

This case uses OpenSSL on the lab host to check a synthetic builder signature and bind the
source file to a deterministic configuration artifact. Missing provenance, different source
bytes, altered artifact bytes and a modified signed envelope each stop promotion before
the Job or ConfigMap exists. The approved artifact is mounted in a native Kubernetes Job,
which checks its digest and reads its exact bytes. The source, signed statement, public key
and signature are inert test fixtures. The statement uses an in-toto and SLSA-shaped
envelope. This exercise establishes no SLSA level.

NIST SP 800-204D names the three stages as artifact, step, or actor compromise;
propagation; and exploitation. This is evidence of a selected provenance and artifact
propagation check. A production threat model, trusted builders and admission, AI supply
chains, operating evidence, and recurring review remain outside this run.

- [NIST SP 800-204D](https://csrc.nist.gov/pubs/sp/800/204/d/final)

## Bounded threat-model structure gate

The case uses inert JSON records to check the defect and attack classifications,
component inventory, and all three NIST attack stages: compromise, propagation,
and exploitation. Each finding uses a unique identifier and links to a
component-owned flow, a mitigation for that stage and component, and evidence
inside the approved stage directory.

The fixture checks rejection of missing attack stages, missing defect coverage,
inconsistent stated intent, missing mitigations, malformed component inventory,
duplicate finding identifiers, and evidence borrowed from another stage.
Changing the graph revision and digest makes the prior review stale. A record
bound to the new graph passes.

The case checks structure and exact graph binding with synthetic actors,
assets, vectors, mitigations, and evidence. Substantive threat coverage,
risk judgments, effective mitigations, reviewer authority, trusted production
builders and deployments, and recurring review require adopter evidence.
The four structure checks preserve the original six provenance and native Job
checks.
