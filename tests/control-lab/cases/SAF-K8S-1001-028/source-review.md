# SAF-K8S-1001-028 source review

## Provenance and boundary

- Catalog control: `SAF-K8S-1001-028` at framework revision `133a8698a45e2b335b51728bf4c62f7bda98d15f`, `markdown/controls/SAF-K8S-1001-028.md`.
- Review date: 2026-11-22.
- The retained result covers the routing behavior on Kubernetes v1.36.1 in a
  dedicated Kind cluster with a metadata-level audit policy.

## Claim review

| Catalog obligation or implication | Primary source and mechanism | Result / evidence needed |
| --- | --- | --- |
| Kubernetes audit logs should be onboarded and forwarded into a SIEM. | [Kubernetes v1.36 audit documentation](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) says audit events originate in `kube-apiserver`, are filtered by policy, and are written to configured backends. It describes log-file and webhook backends; omitting `--audit-policy-file` means no events are logged. | K8s documents configurable event production/backend delivery, not a blanket requirement to forward records to a SIEM. Production policy coverage, backend operation, destination approval, retention, and SIEM integration need deployed-system evidence. The draft proves only one configured metadata audit record reaching its owned receiver. |
| AI workload security sources must include inference, training, registry, policy, and runtime. | The cited [EU AI Act Article 12(2)(c)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng) requires logging capabilities that enable recording events relevant to monitoring the operation of high-risk AI systems referred to in Article 26(5). Article 12(1) addresses automatic recording over the system lifetime; Article 12(2) makes the relevance purpose-appropriate. | The law does not enumerate these five source classes, require Kubernetes, SIEM ingestion, or a security-event taxonomy. Treat the five classes as a local catalog/test taxonomy pending a separately supported risk and system-specific scope decision. Actual AI source generation and completeness require application/product evidence. |
| Crosswalk to high-risk AI record-keeping | EU AI Act Articles 12 and 26 assign specific obligations for high-risk AI systems. Article 12(2)(c) concerns logging relevant to operational monitoring under Article 26(5). | The catalog marks the crosswalk partial. It connects the SAF logging control to that monitoring objective. SIEM onboarding and the selected log classes are SAF implementation requirements within its scope. |
| A real Kubernetes API audit event has an ID suitable for correlation. | [Kubernetes v1.36 audit API schema](https://v1-36.docs.kubernetes.io/docs/reference/config-api/apiserver-audit.v1/) defines `auditID` as required and unique for each request. Audit docs describe request stages and policy-selected fields. | The draft checks one ordinary ConfigMap create: response `Audit-Id` equals the file event `auditID`; `ResponseComplete`, namespace/resource/name/verb match; `Metadata` avoids request/response bodies. This is a fixture-level identity check, not proof of production identity continuity or all-stage handling. |
| Source-to-connector routing proves delivery completeness and health. | These are separate properties. The catalog explicitly excludes monitoring completeness/health after onboarding; case 1001-029 is the separate sink-side completeness check. | The draft asserts only that one disabled route yields a missing receiver event and enabling the route forwards the same fixture event IDs and types. It does not add completeness monitoring, retry behavior, outage detection, sustained delivery, retention, or alerting. |

## Revised test scope

Use a case-owned cluster, namespace, audit policy, source router, and receiver. Generate one real Kubernetes audit record from a normal successful API create. Correlate API response `Audit-Id` to the exact audit-file record. Convert only the relevant metadata into the route fixture and preserve the true `auditID` and declared source origin. Use one harmless object with no credentials or sensitive contents.

Five in-cluster, one-shot fixture Pods submit fixed synthetic event records for inference, training, registry, policy, and runtime. The connector's initial route map contains the Kubernetes audit route only. Each AI source receives a route-missing response and is absent at the receiver. Enable the five routes, replay the same event types and `event_id` values, and assert expected origin and event identity at the receiver. The event ID for the Kubernetes record is runtime-generated, but the expected proof value is deterministic equality among the API response, source audit event, and received event.

Normal API requests and inert fixtures only. There is no exploit or bypass behavior. All endpoints are cluster-local service names; the router, receiver, credentials (none), event data, and API object are case-owned.

## Crosswalk and policy boundaries

The Article 12.2(c) mapping is a normative legal reference whose application depends on whether the AI system is high-risk and the relevant provider/deployer responsibilities. This technical test neither determines that applicability nor interprets “events relevant” for a real system. It does not test the Article 26(5) monitoring procedure, notification duties, or suspension decisions. A future mapping review should keep the catalog relation explicitly partial and avoid implying Article 12 mandates SIEM use or the five named classes.

Kubernetes audit policy defines what the control plane records and at what level. The case's metadata-only rule is intentionally narrow. It does not establish adequate production rules, audit log capacity, tamper resistance, rotation, webhook semantics, or that every API operation is included. Audit policy correctness and data minimization remain environment-specific.

The source origins and AI event-type names in `fixtures.json` are explicit fixture metadata. They are not sourced standard event definitions. A production claim about those meanings needs the emitting application's documented schema and an owner-approved mapping to its operational/security events.

## Disposition

The lab verified one native audit event and five synthetic fixture sources at
the receiver. Deployed source schemas, approved connectors, actual enterprise
SIEM ingestion and the applicability of the partial legal crosswalk require
further evidence.
