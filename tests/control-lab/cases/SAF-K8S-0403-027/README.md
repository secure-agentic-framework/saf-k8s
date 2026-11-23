# SAF-K8S-0403-027 Secret leak incident handling

Run by ID on fresh Kind. The fixture detector submits a finding about a
harmless public marker. A separate actor confirms and owns the incident,
writes the escalation handoff, removes the affected access grant, and
records an observed denial. The unaffected grant remains usable and the
responder retains its case evidence.

The queue is Kubernetes-backed fixture state. Actual on-call delivery,
triage deadlines, provider containment mechanisms and credentials need
their own deployment evidence.

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
