# SAF-K8S-0905-050

This case runs a disposable promotion API in the lab's Kubernetes v1.36.1 cluster. The gate's
service account has only `create` permission for `TokenReview`. The runner mints short-lived,
case-owned ServiceAccount tokens in memory, submits a fixed inert decision to the deployed gate,
and retains only HTTP outcome, TokenReview authentication, username, and returned audience facts.
No token or credential is written to evidence or logs.

The same wrong-audience token must be accepted by the disabled deployment and rejected by the
enabled deployment. Additional enabled-gate probes cover an authenticated but unapproved service
account, a missing credential, and the allowlisted identity. Infrastructure failures, unexpected
HTTP statuses, and TokenReview errors block the run and do not count as control observations.

This validates Kubernetes-issued workload identity and audience enforcement for one fixture gate.
It does not establish human identity, an external OIDC/SSO provider, session-bound approval,
approval-to-model audit binding, or use by production promotion workflows. Run with `python3 lab.py test SAF-K8S-0905-050`.

## Versioned primary references

- [Kubernetes v1.36 authentication and TokenReview](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/)
- [Kubernetes v1.36 TokenReview API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/definitions/token-review-v1-authentication/)
- [Kubernetes v1.36 `kubectl create token`](https://v1-36.docs.kubernetes.io/docs/reference/generated/kubectl/kubectl-commands/)
