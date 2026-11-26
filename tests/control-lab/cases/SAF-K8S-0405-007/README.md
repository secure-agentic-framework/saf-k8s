# SAF-K8S-0405-007 Authenticated API path availability

Run by ID on fresh Kind. The case checks live API readiness and the
response classification of a small number of ordinary sequential reads
before and after applying a dedicated APF flow. The same authorized read
remains available. A single invalid credential and a single authenticated
but unauthorized read distinguish 401 from 403.

The fixture records no credential values. Assess provider endpoints,
service-level evidence, applicable protective controls and effective
capacity independently.

- [Kubernetes API Priority and Fairness](https://v1-36.docs.kubernetes.io/docs/concepts/cluster-administration/flow-control/)
- [Kubernetes API server health](https://v1-36.docs.kubernetes.io/docs/reference/using-api/health-checks/)


The exact paired Kind case has three checks: a real authenticated read before/after an exact APF FlowSchema while readiness remains healthy; one invalid identity observed as HTTP 401; and one authenticated but unapproved identity observed as HTTP 403. These distinguish authentication failure, authorization denial, health and request classification. They do not exercise repeated failed attempts, an identity-provider limit, production capacity, provider alert delivery or recovery objectives.

The paired 0101-007 evidence has 15 checks and adds a bounded ordinary API read queue, measured APF wait, and native concurrency-limit rejection/HTTP 429 with restoration. Use it only as evidence about API-server APF queuing and concurrency; it does not establish failed-login protections.

## Adoption steps

1. Inventory the real Kubernetes API authentication paths and trust boundaries: client certificates, OIDC, token webhook, managed identity integration, and any other enabled authenticator. Name the actual issuer/webhook/provider and the operator responsible for it. Separate authentication from subsequent Kubernetes authorization.
2. For each applicable credential authority, document organization-defined consecutive invalid-attempt threshold, time window, per-user/account basis, and chosen post-limit action (temporary lock, delay, notification, or another approved action). Record unlock/recovery path and denial-of-service safeguards. If a path has no account-style failed-attempt semantics, document the rationale for AC-7 applicability or non-applicability.
3. Use the provider's supported nonproduction or diagnostic procedure with an approved synthetic test identity and a small bounded attempt set. Verify the limit and response after the threshold, normal authorized recovery, and provider audit records. Do not generate high-rate login traffic or test against shared/production identity infrastructure.
4. Capture provider-side health/error metrics and alert ownership for the issuer/webhook independently from Kubernetes `/livez` and `/readyz`. Verify agreed availability, overload, recovery and notification targets using approved service evidence or vendor reports.
5. Inspect the effective API-server/APF configuration and relevant FlowSchema/PriorityLevel rules. Compare with the reference ordinary request classification; where supported, use a small approved workload to observe queue/wait/rejection behavior and selected API health. Record actual API rate/seat budgets and managed-control-plane limits separately.
6. Correlate provider failure/limit observations with Kubernetes API response classification, while keeping 401 authentication failures, 403 authorization denials, APF queueing and transport/provider failures as distinct signals. Show the alert destination, responder, response objective and recovery evidence.

## Conditional AC-7 mapping

Keep the current `supports / moderate / conditional` relation. NIST AC-7 requires an organization-defined consecutive-invalid-logon limit during a defined period and an automatic organization-selected action after the limit. Kubernetes APF governs eligible API request concurrency and queueing; it is not an invalid-login counter. The tested single 401 and 403 do not prove AC-7. Apply the mapping only where the real credential authority separately implements and verifies the applicable AC-7 behavior.

## Sources

- NIST SP 800-53 Rev. 5, release 5.2.0: [official publication](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final); AC-7 source text in NIST's Rev. 5 OSCAL control catalog.
- Kubernetes v1.36: [API Priority and Fairness](https://v1-36.docs.kubernetes.io/docs/concepts/cluster-administration/flow-control/) and [API server health checks](https://v1-36.docs.kubernetes.io/docs/reference/using-api/health-checks/).
