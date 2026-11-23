# SAF-K8S-0905-012

Run `python3 lab.py test SAF-K8S-0905-012` from the control lab directory.
The case asks Kubernetes authorization the same four fixed access questions
before and after granting namespace-local `get` on the named ConfigMaps.
Both subjects start with no access. Each gains its own permitted read and
remains denied across environments.

The same training-named volume declaration is admitted before policy enrollment
and denied by the named production admission binding after enrollment. A
permitted inference Pod reaches Succeeded and reads its inert production
reference. The case uses application-owned fixtures without credentials.
Cloud identity federation, provider IAM, other reference forms and deployed
enrollment require separate evidence.

[Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/) ·
[Kubernetes v1.36 Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
