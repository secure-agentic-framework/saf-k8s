# SAF-K8S-0908-002

From the control-lab runner directory, run `python3 lab.py test SAF-K8S-0908-002`. The owned Kind fixture deploys baseline and governed HTTPS services. The same fixed, benign requests compare public success, validation error, and diagnostics outputs. The governed service requires a purpose-bound projected identity for diagnostics and uses Kubernetes TokenReview and SubjectAccessReview for one named record. The authorized identity can still retrieve the record, and the public serving path retains its documented output.

Review production route and error coverage, trust policies, authorized diagnostic access and logging, network exposure, and evaluated disclosure risk against the approved application contract.

[OWASP API Security API3:2023](https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/)
