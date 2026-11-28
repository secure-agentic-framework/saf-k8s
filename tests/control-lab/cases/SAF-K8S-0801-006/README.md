# SAF-K8S-0801-006 GPU reassignment release gate

From the control lab directory, run
`python3 -Bu lab.py test SAF-K8S-0801-006` with the reviewed catalog index and
local Docker context. The fixture requires Kind, kubectl, and OpenSSL.

The case tests an actual Kubernetes Pod admission gate with synthetic allocation,
transition, and attestation records. The native ValidatingAdmissionPolicy denies
the quarantined request, admits the approved fixture Pod, and denies the old
request after the operator changes the record to a new transition. Further checks
vary the allocation and target trust independently, remove the approval record
and observe the missing-parameter denial, then create a new approval record and
observe the permitted admission.

A scoped HTTPS validating webhook reads the same active approval record through
the Kubernetes API and compares its validity interval with the webhook's clock.
The case checks rejection for missing or future-dated validity and a successful
dry run inside the validity window. The identical request and unchanged record
then produce a named denial of a live Pod create after expiry. The API confirms
the Pod was never persisted, and the same request is admitted after the
approval is renewed. The runner keeps normalized observations from both
the native gate and the elapsed-validity check.

The executable uses an inert CPU workload and synthetic evidence. Verify the
exact device or provider sanitization outcome, trusted evidence producer and
clock, enforced allocation boundary, and approved fallback separately.
