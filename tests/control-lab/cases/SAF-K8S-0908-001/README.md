# SAF-K8S-0908-001 Scoped inference request controls

Run by ID on fresh Kind. Kubernetes TokenReview authenticates two
temporary pod identities with an audience scoped to the test. A TLS
gateway enforces a small quota over an ordinary sequence of requests
to a separate fixed-output predictor. Compare accepted responses,
the predictor's actual call record, and the attributed quota event.
The independent permitted caller continues to receive its result.

Verify the deployed model risk, quota windows, statistical signals,
shared identities, bypass paths, and response workflow separately.

- [Kubernetes ServiceAccounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)
- [Kubernetes TokenReview](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/)

The last comparison makes one ordinary request using a valid projected
identity outside the route's approved set. The governed gateway reports
`credential-unapproved`. Independent gateway and predictor event reads
confirm the request never reached the predictor.
