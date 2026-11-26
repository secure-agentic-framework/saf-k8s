# Verify workload-aware remediation targets

Run `python3 tests/control-lab/lab.py test SAF-K8S-0604-009 --docker-context desktop-linux` from the framework checkout.

The four-check portable case exercises a fictional finding workflow with a versioned deterministic policy: severity-only baseline; risk-context reprioritization and deadline assignment; incomplete context routed to triage; unauthorized deferral ignored; approved exception expiry without moving the original target; overdue blocking; and verified remediation that preserves missed-target history. It does not establish the organization's risk policy, real findings, operational SLA performance, third-party monitoring, or integration coverage.

1. Approve and version risk classes, context factors, owner routing, target deadlines, clock start/timezone, escalation and exception authority. Keep severity distinct from final contextual risk decisions.
2. Inventory actual AI workload artifacts and owners. For each vulnerability record, link evidence to exact workload/image identity and record relevant severity, threat/exposure, workload purpose/role and confidence. Missing or stale context must route to timely human triage.
3. Trace an actual representative record through priority, owner, due time, escalation and overdue state. Show the policy revision and clock source used; reconcile all in-scope clusters, training, inference and preprocessing paths.
4. Verify exception authority, decision reason, exact finding and artifact scope, start, expiry and reviewer. Confirm expiry does not silently extend the original target and that the missed-target history remains visible.
5. Close only after independent evidence verifies remediation for the same affected artifact/component and version. Preserve the initial record, response, verification source/time, and late history.
6. For NIST AI RMF MANAGE 3.1, separately identify which actual third-party AI technologies/resources are in scope; show recurring risk monitoring and documented controls. Kubernetes-hosted AI workload status alone does not make a resource third-party.
7. For SSDF RV.2.1, retain the risk-analysis evidence and response rationale for real findings. The case's fictional severity/context policy proves deterministic behavior only, not sufficiency of an organization's risk analysis.

## Sources

- NIST AI RMF Core/Playbook, MANAGE 3.1: [Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/) and [Manage Playbook](https://airc.nist.gov/airmf-resources/playbook/manage/).
- NIST SP 800-218 SSDF Version 1.1: [official publication](https://csrc.nist.gov/pubs/sp/800/218/final).
- The case review also cites [NIST SP 800-40 Rev. 4](https://csrc.nist.gov/pubs/sp/800/40/r4/final) and [FIRST CVSS v4.0 Specification](https://www.first.org/cvss/v4.0/specification-document) as context, not as substitutes for the organization's approved risk policy.
