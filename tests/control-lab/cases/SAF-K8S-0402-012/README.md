# SAF-K8S-0402-012 — Ephemeral training job credential expiration

From the framework repository, run:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0402-012 --docker-context desktop-linux
```

The fresh Kind run uses Kubernetes v1.36.1. Allow about 12 minutes after the cluster starts. It waits for the original projected credential to expire using the existing clock and allows the API server's JWT clock skew. The runner saves a sanitized `expiry-timing.json` beside the receipt.

- **Red.** Release the first Job after its projected token is issued. The token still authenticates as the expected Pod-bound identity in TokenReview while its terminal Pod exists and the token has time left. Check the second Job's issued 600-second lifetime and successful authentication before expiration.
- **Green.** The original token is rejected by TokenReview after the issued expiration while its original Pod remains running. The case holds that token only in process memory and never passes it in CLI arguments or logs.
- **Permitted.** A fresh same-audience projection from a third Pod and Job still passes TokenReview using the same audience and service account.

Configure expected-duration TTLs for each credential type and measure the lifetime actually issued. Use separate lifecycle cleanup when a terminal Job must invalidate credentials before their expiry. The test covers the native API server, so use provider or relying-party evidence for Vault, cloud IAM, databases, and deployed jobs.

[Kubernetes service account administration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/) · [v1.36.1 token issuance](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.1/pkg/registry/core/serviceaccount/storage/token.go) · [v1.36.1 claims validation](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.1/pkg/serviceaccount/claims.go)
