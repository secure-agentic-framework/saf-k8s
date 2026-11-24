# SAF-K8S-0905-044 public-model intake quarantine and release

`python3 tests/control-lab/lab.py test SAF-K8S-0905-044 --docker-context desktop-linux`

An owned Kind cluster accepts an unchecked metadata-only reference in the
baseline. The quarantine namespace sets restricted Pod Security admission
and records a default-deny NetworkPolicy. A server dry-run confirms
restricted admission refuses a nonconforming Pod. A synthetic offline
scanner decision rejects unsafe, missing or mismatched inputs.

The release namespace requires the exact reviewed metadata SHA-256 in a Pod
annotation and a clean decision. Native admission refuses a different
digest in server dry-run. Kubernetes authorization refuses a distinct
unapproved ServiceAccount. The authorized principal creates an inert release
Pod that becomes Ready and carries the exact reviewed digest.

Actual malware scanners, model artifact bytes, network enforcement packets,
trusted evidence issuance, and production release paths require separate
validation. No model code or scanner payload runs.
