# SAF-K8S-0104-017 CIS Benchmark exception approval and re-review

Run the case in a disposable Kubernetes v1.36.1 kind cluster.

```sh
python3 lab.py test SAF-K8S-0104-017 --docker-context desktop-linux
```

The [catalog control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0104-017.md)
requires a risk owner to approve accepted findings, document the rationale and
compensating controls, and reassess each exception on a defined schedule.
CIS Kubernetes Benchmark v2.1.0 covers Kubernetes 1.36 and 1.37. CIS-CAT Pro
Dashboard supports benchmark-version-specific exceptions, dates, rationale, and
an authenticated approval workflow. The SAF requirements also prescribe
risk-owner approval, compensating controls, and recurring reassessment.

The API admits an incomplete synthetic ConfigMap before the example
ValidatingAdmissionPolicy is installed. The policy then denies that same
request, permits a complete exception, and denies a proposed update that
moves the review deadline before the fixture date. A read confirms the
accepted object still has the original deadline. The policy applies only to
labeled fixture ConfigMaps in the labeled test namespace.

This example validates governance record fields and dates. Evidence of a
real approval, functioning compensating controls, scheduled reassessment,
and production coverage must come from the actual exception workflow.

- [CIS Kubernetes Benchmark v2.1.0 release notes](https://www.cisecurity.org/insights/blog/cis-benchmarks-november-2026-update)
- [CIS-CAT Pro Dashboard exception workflow](https://ciscat-pro-dashboard.docs.cisecurity.org/en/stable/source/Dashboard%20User%27s%20Guide/)
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
