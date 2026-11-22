# SAF-K8S-1005-001 — Synthetic Kubernetes incident response exercise

This case provides a repeatable red/green/positive exercise for synthetic role
ownership, timeline quality, evidence integrity, mock-workload containment and
recovery, and post-exercise review. It runs in one fresh Kind v1.36.1 cluster.
The mock Deployment uses a digest-pinned Python image, has no service-account
token, drops all Linux capabilities, and sleeps without network or application
activity. Fixtures use invented `urn:example:` roles and synthetic incident IDs.

The case configures the Kubernetes API server audit log backend at `Metadata`
level for the disposable namespace. It captures raw matching audit JSON lines
and a filtered summary of event IDs, timestamps, actors, object references, and
response codes. Metadata level excludes request and response bodies. The fixture
evidence payload is intentionally public and contains no credentials, secrets,
real indicators, external feed data, or target information.

The expected phases are:

- Red: missing commander and handoff, out-of-order timeline, incorrect evidence
  digest, unreviewed closure, and mismatch rejection are detected.
- Green: named synthetic owners and accepted handoff, ordered timestamped
  records, hashed immutable snapshot, namespace-scoped scale-to-zero, exact
  digest-pinned recovery, independent review, owned follow-up, and audit records
  satisfy the exercise checks.
- Positive: a second support role preserves ownership, the mock workload runs
  before and after containment, and review explicitly retains production
  validation as `unverified`.

The run writes `audit.case.raw.jsonl`, `audit.summary.json`, the standard runner
command transcript, and per-check result JSON.

## Source claim correction and boundaries

The original control referenced NIST SP 800-61 Rev. 2. Final Revision 3
superseded it in April 2025 and is cited by the corrected control. Rev. 3 aligns incident
response with NIST CSF 2.0 risk-management activities; it does not preserve the
control's five named phases as the current NIST model. This exercise keeps the
catalog's lifecycle language as its test outline, not as a claim that Rev. 2 is
current or that Rev. 3 mandates this exact sequence.

Kubernetes auditing documents chronological security-relevant records, the
`kube-apiserver` audit event lifecycle, policy-selected fields and backends.
The exercise proves only that selected metadata for its synthetic API
operations appears in this temporary cluster's local audit log. It does not
prove complete audit-policy coverage, external log forwarding, durable or
tamper-resistant storage, retention, SIEM integration, forensic completeness,
or evidentiary chain of custody.

The cluster exercise cannot establish organizational role assignment,
out-of-band communications, legal notifications, production evidence handling,
real AI workload procedures, deployed detection quality, eradication decisions,
business recovery criteria, or annual exercise cadence. These remain separate
organizational evidence requirements. There are no real incident records,
feeds, targets, exploit procedures, attack payloads, or sensitive evidence in
this case.

Primary sources:

- [NIST SP 800-61 Rev. 3 final publication](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST April 2025 announcement that Rev. 3 supersedes Rev. 2](https://csrc.nist.gov/News/2025/nist-revises-sp-800-61)
- [Kubernetes v1.36 auditing documentation](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
