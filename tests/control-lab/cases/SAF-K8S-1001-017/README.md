# SAF-K8S-1001-017 — Audit distinct API authorization and admission decisions

```sh
python3 lab.py test SAF-K8S-1001-017 --docker-context desktop-linux
```

From the framework checkout, run `python3 tests/control-lab/lab.py`.
This test configures file audit logging on a disposable Kubernetes v1.36.1
control plane. It uses inert resources and synthetic users only.

A comparable denial outside the audit scope produces no selected event.
Within scope, the fixture distinguishes an RBAC denial from a validating
admission policy denial. It checks the API decision and the exact audit
annotations including the effective identity. An approved request leaves a
visible ConfigMap. Request-level rules separately retain the defined inputs
for an inert Role create and a real SubjectAccessReview. They omit response
bodies. The raw evidence retains the selected audit events and API responses.

The [Kubernetes v1.36 audit annotation reference](https://v1-36.docs.kubernetes.io/docs/reference/labels-annotations-taints/audit-annotations/)
shows which decision details can appear at Metadata level. The
[validating admission policy documentation](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
describes the Audit and Deny actions. For the
[pinned SAF control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-1001-017.md),
actual metrics API requests, webhook-specific paths, managed audit systems,
and the production authorization and operations inventory need further evidence.
