# Source review — SAF-K8S-1001-031

## Provenance and pin verification

- Requested original revision: `secure-agentic-framework/saf-k8s` commit `133a8698a45e2b335b51728bf4c62f7bda98d15f`.
- Verified that the commit object exists in the local framework repository and that `markdown/controls/SAF-K8S-1001-031.md` exists at that tree.
- SHA-256 of the pinned control markdown: `e5169cc52e4077e8b131d2abeb68a32f2a83b8af9b3d228e41145020bb5336a7`.
- Pinned source: [control markdown](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-1001-031.md); [catalog YAML](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/saf_k8s_controls.yaml#L10621-L10640).
- The framework checkout currently points at `8498e6b0c2ee005027a70a148c62eb6a3ae3b171`; the control text at the requested pin was read with `git show`, not inferred from the checkout's current file.

## Obligation review

| Catalog obligation | Mechanism / applicability | Evidence the proposed case can provide | Source review result |
| --- | --- | --- | --- |
| Preserve source context | Centralized records need identifiable Kubernetes origin. | Fluent Bit's Kubernetes filter is configured to derive namespace, Pod, and container identity from the record tag and fetch Pod metadata; HTTP receiver checks all three on every record. | Mechanism is plausible and testable. A local synthetic receiver does not establish a production source taxonomy or all log classes. |
| Preserve tenant context | Tenant attribution must not be trusted from unverified application payload. | Fixture tenant value exists only in Kubernetes Pod labels. The event JSON contains event ID and marker only. Receiver requires its tenant assignment to match the fixture Pod label. A fifth Pod omits the label and must be detected as missing context. | Strong deterministic check of metadata enrichment and missing-label detection. Label governance and tenant label correctness in production remain outside this fixture. |
| Preserve workload context | Records must be attributable to a workload. | Workload value exists only in Kubernetes Pod labels; distinct fixture Pods and markers cover inference and training for both tenants. | Checkable for the named synthetic Pods. Does not establish metadata coverage for other controllers or AI workloads. |
| Segregate/search centralized streams | Tenant/workload dimensions must produce useful exact searches and no cross-tenant results. | Fixture receiver performs exact equality searches over the actual HTTP-ingested events by tenant and tenant/workload; asserts expected IDs and rejects extras, duplicates, and crossed results. | Demonstrates fixture-level searchable segregation only, not backend ACLs, production index/view authorization, retention, or SIEM behavior. |
| Retain context through transport | Scope excludes initial collection and routing, but event context must still be present at the centralized record after transport. | Actual Fluent Bit tail → Kubernetes filter → HTTP output → local receiver pipeline; compare received records, not collector stdout or config. | End-to-end transport here is a bounded proof point, not a claim that control scope mandates collector installation or route availability. |

## Upstream behavior checked

- The official [Fluent Bit v5.1.2 release](https://github.com/fluent/fluent-bit/releases/tag/v5.1.2) confirms the selected version exists. The image digest is reused from framework case `SAF-K8S-1001-029`; the v5.1.2 tag/digest relationship should be confirmed by the parent when pulling the image.
- The official [Kubernetes filter manual](https://docs.fluentbit.io/manual/data-pipeline/filters/kubernetes) documents `regex_parser` as extracting `pod_name`, `namespace_name`, and `container_name`, plus metadata enrichment from Pod labels. The proposed configuration uses Pod labels only and disables namespace labels. The [Tail input manual](https://docs.fluentbit.io/manual/data-pipeline/inputs/tail) documents file tailing and the [HTTP output manual](https://docs.fluentbit.io/manual/data-pipeline/outputs/http) documents `json_lines`. The official [v5.1.2 release](https://github.com/fluent/fluent-bit/releases/tag/v5.1.2) confirms the selected version exists.
- Neighboring framework case `SAF-K8S-1001-029` pins Fluent Bit `5.1.2` to `cr.fluentbit.io/fluent/fluent-bit:5.1.2@sha256:d792375ca8e53be72fc25716c28f291f32c6fc6f4f31d12d0d14bc78cefe9226`; this draft reuses that already-reviewed image pin. Version-specific configuration compatibility still needs the parent's run to establish.

## Disposition

The fixture receiver confirms source identity, tenant and workload metadata,
exact search membership, and detection of the unlabelled record. Production
metadata correctness, backend authorization, durable retention and operating
procedures require separate evidence.
