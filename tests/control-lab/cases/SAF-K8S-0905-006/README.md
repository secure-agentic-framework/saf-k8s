# SAF-K8S-0905-006 — Verify model retirement and dependent notice propagation

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-006 --docker-context desktop-linux` from the framework checkout.

The case includes eight checks for inert model records, a fixed lineage graph and owned storage. A ninth check uses a pinned Zot v2.1.23 OCI registry. A separate repository stores the exact same inert artifact manifest and layer. The fixture deletes the source-repository manifest by digest, reads the archive copy by immutable digest, restores from bytes fetched back from the archive repository, and compares an independently reconstructed expected manifest and layer digest.

The artifact manifest carries fixed metadata tying it to `fixture-lineage-v1`, source `fixture-dataset`, and graph node `model-archive`. This is a metadata reference to the already-tested fixture graph; it does not parse or validate ML-BOM/CycloneDX. Both repositories share one Zot process and one ephemeral `emptyDir` backend. The supplement demonstrates repository-level archive/readback in a bounded reference, not independent backup, cold storage, provider retention, or disaster recovery.

The Zot Service is ClusterIP-only, named and case-owned, and the probe's URL is fixed to that Service. Zot permits anonymous read/create/delete only for the two exact fixture repositories; no registry credential is created or used. The probe blocks redirects and checks every upload Location remains on the internal case Service. The probe Job is tokenless, non-root, read-only apart from its read-only mounted code, with no network exposure outside the disposable cluster. It emits only statuses, digests, fixed lineage identifiers and booleans, never artifact bytes.

## Verify an adopted model lifecycle

1. Inventory exact version identities and authoritative model stores, deployment references, archives, backups, caches, replicas and retained copies. Record who can authorize deprecation, archival, release removal and disposition. Verify archive integrity and approved restoration where applicable.
2. Reconcile ML-BOM and actual provenance identifiers to every affected parent, release and downstream artifact in the applicable environment. Trace an authorized correction or deletion notice through every affected dependency and assign the required follow-up. Verify the actual action and distinguish unresolved records.
3. Follow a governed retired version through withdrawal and approved disposition. Verify the supported provider, storage and key procedures for the actual copies in scope, applicable retention, backups and recovery, and independent authorization and outcome evidence.
4. Record how privacy and data-governance owners decide applicable obligations and exceptions for each case. Retain sanitized identifiers, version history, decision provenance and verified outcomes.

- [Kubernetes Persistent Volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/)
- [Zot v2.1.23 configuration](https://zotregistry.dev/v2.1.23/admin-guide/admin-configuration/)
- [OCI Distribution Specification v1.1.0](https://github.com/opencontainers/distribution-spec/blob/v1.1.0/spec.md)
- [GDPR, Articles 16 and 17](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng/)
- [EDPB Opinion 28/2024 on AI models](https://www.edpb.europa.eu/system/files/documents/2024-12/edpb_opinion_202428_ai-models_en.pdf)


## Bounded CycloneDX 1.6 ML-BOM lineage ingestion

The additive fixture parses a selected CycloneDX 1.6 JSON subset: BOM header and
version; component type, `bom-ref`, name, version and three case-specific
ConfigMap-binding properties; and dependency `ref`/`dependsOn` entries. It checks
unique references, one explicit dependency row per component, rejects unknown
references, and interprets each `dependsOn` edge in reverse to identify downstream
components. It binds all six inert, versioned data/model records to the exact
`ConfigMap` namespace/name/UID and checks the live record kind and version.
Notices are applied only to the source and transitive dependent ConfigMaps using
JSON Patch UID and resourceVersion preconditions; an unrelated component stays
unmarked. An unknown-reference counterfactual is rejected before any notice
mutation. The parser is not a complete CycloneDX schema validator and does not
verify BOM provenance or signature.

The fixture proves API-object notice propagation for this fixed graph only. It
does not establish production ML-BOM reconciliation, deployed registry lineage,
complete model/data inventory, notice authorization, permanent erasure,
physical or backup deletion, cryptographic erasure, retention compliance, or
regulatory compliance. Permanent disposition of actual stored copies remains
adopter evidence. The original nine checks remain in the case.

- [CycloneDX v1.6 JSON reference](https://cyclonedx.org/docs/1.6/json/)
- [CycloneDX v1.6 JSON schema](https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json)


## CycloneDX subset ingestion supplement

The added fixture is CycloneDX 1.6 JSON with versioned `data` and
`machine-learning-model` components, component `bom-ref` values, and dependency
rows. The local parser checks only the fields used to resolve the fixed fixture;
it is not the complete official schema validator. It rejects unresolved dependency
references before side effects, builds downstream links by reversing `dependsOn`,
and maps each component's case-specific namespace/name/kind/version properties
to a live ConfigMap UID. Notice annotations use JSON Patch `test` operations on
UID and resourceVersion, followed by independent readback. A deliberately stale
UID precondition and an unknown dependency reference must produce no partial
mutation.

The supplement adds three checks and retains all nine published checks. It proves
only finite object-level lineage and notice handling for inert lab records. Actual
ML-BOM source reconciliation, complete schema validation, authorization, archive
independence, retention, permanent or cryptographic erasure, backup/replica
disposition and compliance remain unverified adopter evidence.

- [CycloneDX v1.6 JSON reference](https://cyclonedx.org/docs/1.6/json/)
- [CycloneDX v1.6 JSON schema](https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json)
