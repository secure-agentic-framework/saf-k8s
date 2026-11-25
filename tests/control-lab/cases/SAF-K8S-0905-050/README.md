# SAF-K8S-0905-050 authenticated model promotion review

Run the reference test in the framework checkout:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0905-050 --docker-context desktop-linux
```

The thirteen checks distinguish workload identity and a synthetic human
reviewer. The ServiceAccount comparison exercises an explicit promotion
TokenReview audience. With enforcement enabled, the gate rejects the same
wrong-audience request accepted by the baseline, along with missing and
unapproved credentials. It accepts the approved ServiceAccount.

A separate gate calls native TokenReview for an owned synthetic OIDC JWT.
It uses TokenReview's implicit Kubernetes API audience. The API server's
configured JWT authenticator independently verifies the JWT's promotion
audience. The gate verifies the authenticated reviewer and selected group,
then checks the signed fixture session and exact artifact target. Kubernetes
SubjectAccessReview verifies the named approval permission. The test rejects
a different session, artifact, reviewer and signed JWT audience. Removing
the scoped grant denies approval while the same reviewer still authenticates.
Restoring the API removes the temporary issuer and the same synthetic JWT is
no longer authenticated. The receipt contains sanitized decisions.

## Verify an adopting implementation

1. Inventory each approval entry point, the participating identity providers,
   issuer and audience policy, trusted roots, MFA requirements, and session
   issuance and expiry. Identify all human and automated reviewer roles and
   who can independently grant and withdraw permission.
2. Bind the approval to the authenticated reviewer session and exact target
   at the live decision boundary. Exercise a valid scoped approval, a
   mismatched or expired session, a different target, a different reviewer,
   and missing or wrong-audience credentials using authorized test identities.
3. Withdraw the exact approval grant and verify that identity authentication
   alone no longer allows that reviewer to approve. Repeat wherever promotion
   can be initiated. Retain bounded decision, timing and role evidence.
4. Review separately any downstream audit-record binding and transfer
   between security domains. The synthetic promotion decision demonstrates
   the local authentication, session, target and authorization mechanism.

[Kubernetes v1.36 authentication](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/)
and [the pinned API server's JWT audience adapter](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/kubeapiserver/authenticator/config.go).
