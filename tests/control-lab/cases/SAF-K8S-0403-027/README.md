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

From the SAF-K8S repository root, run `python3 tests/control-lab/lab.py test SAF-K8S-0403-027 --docker-context desktop-linux`.

## Adopter verification

With an approved public marker, verify each applicable detector or reporting surface delivers the required incident attributes. Record the actual responder and owner, corroboration, severity, assigned clocks and intended containment. Execute only the selected safe workflow in approved scope and verify the relevant accepting path refuses the retired synthetic grant while the unaffected operation still succeeds. Retain actual escalation receipt, containment timing, restored or remaining access, and work handoff.
