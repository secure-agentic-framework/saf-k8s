# SAF-K8S-0910-033 cross-cluster investigation

Run `python3 lab.py test SAF-K8S-0910-033` from the control-lab directory.

The published case already demonstrates one harmless threshold-triggering cross-cluster transfer, an authenticated independent receiver observation, a source Pod receipt written via its own bounded API rights, a native Metadata audit event correlated to the originating Pod UID, a read-only investigator retrieving an immutable report, and `unknown` dispositions when evidence is missing or inconsistent. The four checks include the original three comparisons and a structured report check.

The additive check makes the required report elements explicit instead of relying on readers to infer them from evidence fields:

- `scope`: trace, source identity and API UID, source Pod UID, receiver service, and receiver API UID;
- `findings`: bounded summary plus exact received/source digest and audit-event correlation booleans;
- `disposition`: the exact known synthetic fixture classification.

It preserves the original missing-evidence and inconsistent-evidence unknown outcomes. This verifies only a structured reference record for one known synthetic event. It does not represent an actual misuse incident, analyst investigation, approved organization workflow, notification, containment, or recovery.

Adopters still need to define authorized investigators/approvers, intake and severity criteria, investigation scope and evidence sources, findings/disposition requirements, incident response actions and escalation, protected retention, and review of real production alerts.
