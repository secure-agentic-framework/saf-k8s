# SAF-K8S-0604-008 — AI workload vulnerability exposure classification

Run the published six-check case from the framework checkout:

    python3 tests/control-lab/lab.py test SAF-K8S-0604-008 --docker-context desktop-linux

## What the paired fixture establishes

The current case has five base checks and one purpose-record check:

1. A finding without component or workload context is classified unknown.
2. Live Job/Deployment ownership, Pod identity, labels and observed image IDs distinguish the synthetic training and inference fixtures; missing purpose hints stay unknown.
3. Fictional node and container component records classify only when bound to exact observed node/image identities; absent records stay unknown and disagreements or misbindings become conflicts.
4. A harmless in-cluster request reaches the exact inference Pod through its private ClusterIP Service and ready EndpointSlice. Public reachability remains unknown.
5. The running inference container's BusyBox version is read from the existing fixture Pod and bound to its pinned image reference/runtime imageID. It is compared only to the reviewed OSV CVE-2023-42365 exact CPE-version extract: 1.37.0 is not listed, and the inert 1.36.1 comparator is listed. This is not general version-range evaluation or proof that 1.37.0 is secure.
6. An immutable case-owned ConfigMap stores a synthetic purpose record with fixed source URI/revision and review window. Exact workload, Pod, image, and owner identities bind the positive training/inference classifications. Missing, expired, unknown-revision, or tampered records classify unknown; misbound and duplicate entries classify conflict.

The test does not install or exercise vulnerable software, generate exploit payloads, or test vulnerability behavior. It demonstrates bounded context-joining and uncertainty behavior using inert fixtures.

## Paired evidence

The current published receipt has six matched checks on each independent v1.36.1 Kind run; both clusters were deleted:

- Lab: 20261127T035545Z-70b8950a
- Framework: 20261127T035731Z-60cc8269

Each run retains exposure-context.json, package-advisory-observations.json, and purpose-provenance.raw.json. Dynamic identities and full fixture records remain in raw evidence. The normalized receipt reports only stable classifications and booleans.

## Adopter evidence remains separate

The fixtures use fictional component records and a synthetic purpose ledger. They do not establish organization-approved purpose or release provenance, full image/SBOM coverage, actual host GPU/device-plugin/injected-runtime inventory, advisory-feed freshness or scanner completeness, deployed ingress/gateway/public reachability, data sensitivity, or organizational risk prioritization.

For a governed deployment, bind findings to authorized workload-purpose and release records; inventory exact image, host, driver, device-plugin, and injected components with their source and version; compare each component to applicable current advisories; measure the actual private and external service paths; retain missing/conflicting coverage; and separately document impact/likelihood, risk tolerance, resource decisions, and treatment.

## NIST AI RMF 1.0 MANAGE 1.2 mapping

The single related mapping is a weak, conditional supports contribution. NIST AI RMF 1.0 Table 4 states MANAGE 1.2 as: “Treatment of documented AI risks is prioritized based on impact, likelihood, and available resources or methods.” This fixture provides some technical context that a separate risk-treatment process may consume. It does not determine impact or likelihood, set tolerance, allocate resources, or select treatment.

Primary title source: NIST AI RMF 1.0, Table 4, MANAGE 1.2:
https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf?download=true
The AIRC Playbook is supplementary guidance; its current page words the resources/methods phrase with “or,” while the mapping title follows the AI RMF 1.0 core text.
