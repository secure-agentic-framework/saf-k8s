# SAF-K8S-1005-019 — Disclosure intake and triage readiness

This case runs one tokenless, digest-pinned Python Job in a disposable Kubernetes v1.36.1 Kind cluster. It reads only the checked-in fictional policy and report fixtures, applies a fixed fake clock, and writes machine-readable raw output from the Job to the lab evidence directory. It makes no network requests and contains no vulnerability details, reproduction steps, payloads, real targets, real contacts, or credentials. Every email and URL uses the reserved `.invalid` namespace.

The red observations show that a missing policy is not ready and a synthetic high-severity record beyond its stated mock triage target is flagged. The green observation requires a complete mock policy and on-time responses for all tested severity tiers. The positive observation confirms separate declared intake channels for synthetic internal and external reports, acceptance of anonymous external intake, and referral-only handling for an out-of-scope mock record. The actual SLA values, categories, timestamps, contacts, and records are invented test data; they are not proposed service commitments or normative deadlines.

## Source basis

The official Kubernetes security page states that suspected issues may be submitted through its bug bounty program or private security email, and that each report is acknowledged and analyzed within three working days. It also describes keeping the reporter updated during triage and release planning. This is evidence for contact and response-expectation fields in this case, not a severity-tiered SLA requirement. [Kubernetes Security and Disclosure Information](https://kubernetes.io/docs/reference/issues-security/security/)

CISA's official VDP template describes defining authorized scope, allowed and disallowed activity, report submission channels, anonymous reporting, and what the reporter can expect. Its example acknowledgment commitment is within three business days. CISA's Binding Operational Directive 20-01 requires covered U.S. federal agencies to set and track target timelines for acknowledgment, initial assessment/triage, and resolution; it does not prescribe universal or severity-based deadlines and is not asserted to bind this fictional case or other organizations. [CISA VDP Template](https://www.cisa.gov/vulnerability-disclosure-policy-template), [CISA BOD 20-01](https://www.cisa.gov/news-events/directives/binding-operational-directive-20-01).

The pinned control's severity-based SLA requirement is tested as a local control criterion. The reviewed primary sources support having clear response expectations and tracked targets, but do not establish the case's tier names or minute/hour thresholds as universal standards.

## Coverage and limits

This is a defensive readiness test of fixture validation and fake-clock SLA evaluation. It does not prove that a real policy is published or maintained, that a real intake address/form is monitored, that scope language is legally effective, that any party has granted authorization for real testing, or that production reports are tracked, communicated, triaged, remediated, or resolved on time. It does not exercise actual Kubernetes/AI/GPU components, reporter communications, or severity assignment. The control's governance claims beyond these synthetic checks require independent documentary and operational evidence.

## Verify an adopting implementation

Approve the published and internal disclosure policies,
scope, severity definitions, triage clocks, escalation/referral paths, and
closure authority. Route controlled harmless intake records through every
real channel; retain timestamps, acknowledgement, owner, escalation, and
tracking evidence. Verify a deliberately late and out-of-scope report reaches
the correct escalation without preserving sensitive report content in test
receipts.
