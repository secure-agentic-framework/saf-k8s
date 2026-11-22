# SAF-K8S-0605-007 — Admission webhook failure policy and timeout

```sh
python3 lab.py test SAF-K8S-0605-007 --docker-context desktop-linux
```

The Kubernetes v1.36.1 API defaults both webhook types to a ten-second
call timeout and `Fail`. Server-side requests accept one and thirty seconds
and return field validation errors for zero and thirty-one seconds.

One case-owned HTTPS AdmissionReview service accepts ordinary ConfigMaps and
delays marked ones. The test confirms each exact webhook path is active before
comparing the same marked request with a two-second operational timeout.
`Fail` rejects without persisting the object. `Ignore` persists it without a
timed-out mutation. The fixture observes the relevant slow request in each
mode. A healthy mutating request leaves the expected inert label.

With the selected webhook Service unavailable, a matching request fails
while a ConfigMap GET and an excluded namespace's CREATE remain available.
The receipt uses bounded timing classifications and only case fixture data.

Deployed dependencies, aggregate admission latency and production resilience
require separate evidence.

[Kubernetes v1.36 dynamic admission](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/) ·
[Kubernetes webhook good practices](https://v1-36.docs.kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/)
