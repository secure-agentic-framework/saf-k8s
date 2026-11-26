# SAF-K8S-0910-019 member suspension and readmission

Run `python3 lab.py test SAF-K8S-0910-019` from the control-lab directory.
Each arm uses an isolated hub and a separate member. Keep both arms within
the host's cluster concurrency limit.

The hub records a scoped operator's suspension and a separate reviewer's
readmission approval. Before suspension, actual placement into the member
works. During suspension, Kubernetes refuses new placements and the owned
existing workload is drained. The same operator cannot approve re-entry.
The approved member subsequently runs one distinct fixture placement.

This exercises a case-owned administrative workflow and real Kubernetes
authorization. Existing production federation controllers, signal trust,
credential revocation and policy exceptions require independent evidence.

## Signal-source identity

The fixture evaluates fixed clear and isolation signals. The native TokenReview
API verifies the short-lived fixture ServiceAccount identity and exact audience.
The evaluator also checks the governed member UID. A clear signal leaves
both records unchanged and allows an ordinary Deployment to become Ready.
An unapproved source or mismatched member leaves the records unchanged.
An authorized exact isolate signal gates the existing operator workflow.

Inspect the adopted telemetry source, transport and member identity independently.
Exercise observed signal-to-hold timing, work already in flight, retry behavior,
effective credential revocation and placement scopes. Verify independent
readmission and retain the exact member, decision and restored-route evidence.
