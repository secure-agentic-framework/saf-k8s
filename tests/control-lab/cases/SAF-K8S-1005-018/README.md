# SAF-K8S-1005-018 — Component integrity before restoration

This case exercises a defensive recovery gate in one disposable Kind Kubernetes v1.36.1 cluster. It uses two isolated mock Deployments, one immutable ConfigMap with inert case-owned bytes, and a synthetic release record whose exact file bytes are pinned by SHA-256. The case checks the release identity placeholder, an exact component inventory, digest-pinned mock images, a SHA-256 match for the mounted bytes, and Deployment plus Pod readiness observed through the Kubernetes API after promotion.

The runner verifies a real API counterfactual. Skipping the fixture workflow gate creates the mock Deployments with mismatching evidence. After cleanup the enabled gate leaves the Deployment inventory empty for both mismatching and missing evidence. Matching evidence creates the same two Deployments, which become Ready and report the approved mounted digest. The gate is part of the fixture promotion workflow and does not install an admission policy. The case also retains a raw JSON evidence file with only synthetic identifiers, digests, Kubernetes UIDs, and readiness observations. It has no credentials, actual incident artifacts, real feeds, external targets, or production systems.

| Control claim | Evidence |
| --- | --- |
| Verify a known release identity before promotion | Exact synthetic release ID and release-record SHA-256 pinned in the case |
| Verify components affected by an incident | Exact two-item mock inventory; image references and inert mounted bytes checked against fixture values |
| Require observed restoration readiness | Deployment generation/availability, Pod Ready condition, container readiness, and mock startup digest read back after promotion |
| Prevent reinfection or persistence across real recovery | Unverified: there is no compromised baseline, real artifact, signature authority, trusted registry, or production control path |
| Verify nodes, drivers, and all related components | Unverified: this case covers only two mock Deployments |

The release identity and approval fields are synthetic fixture metadata. SHA-256 matching proves byte equality only; it does not authenticate a signer, registry, approval authority, source build, or chain of custody. The case does not test an actually compromised component or prove a production recovery gate. Node operating-system integrity, GPU drivers, real image provenance/signatures, admission enforcement, model artifacts or safety, production traffic readiness, and organization-wide inventory completeness remain outside its evidence.

Run with `python3 lab.py test SAF-K8S-1005-018 --docker-context desktop-linux`. NIST CSF 2.0 outcomes RC.RP-03 and RC.RP-05 cover verification of restoration assets and the restored state. The test exercises these concepts with an inert Kubernetes fixture.

- [NIST CSF 2.0 outcomes and implementation examples](https://csrc.nist.gov/projects/cybersecurity-framework/filters)
- [Kubernetes 1.36 image digests](https://v1-36.docs.kubernetes.io/docs/concepts/containers/images/)
- [Kubernetes 1.36 Pod readiness conditions](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/pod-condition/)
- [Kubernetes 1.36 readiness probes](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/probes/)
- [Kind cluster image selection](https://kind.sigs.k8s.io/docs/user/quick-start/#creating-a-cluster)
- [Docker Official Images Python metadata](https://github.com/docker-library/official-images/blob/master/library/python)
- [Official Python image manifest digest details](https://hub.docker.com/layers/library/python/3.13.18-slim-trixie/images/sha256-1cb6aa9f7b703f1f52a9865d9912ee79b9864da59e8f22a513c9358b6df1fef8)

## Adopter verification

1. Define the authoritative release identity, signing/provenance roots, component inventory, trusted recovery registry, and independent custody for each restoration source, including node OS, drivers, images, and model artifacts.
2. In an isolated recovery environment, verify signed provenance and inventory before promotion. Demonstrate missing, stale, mismatched, or untrusted evidence prevents the recovery workflow from deploying.
3. For an approved known-good candidate, verify signature and digest from the independent trust source, then observe exact component readiness and an authorized service-level recovery check before production return approval.
4. Retain trust-root custody, provenance/inventory results, readiness and decision records, reviewer authority, and exceptions. Keep real incident artifacts and credentials out of the test receipt.
