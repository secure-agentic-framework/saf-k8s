# SAF-K8S-0402-013 — Ephemeral training job credential rotation

From the framework repository, run:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0402-013 --docker-context desktop-linux
```

Allow about 12 minutes after the Kubernetes v1.36.1 cluster starts. The case gives a Job Pod one explicit projected token with a 600-second requested lifetime and a synthetic audience. It checks the expected audience, ServiceAccount, and bound Pod through the Kubernetes TokenReview API.

- **Red.** A client that caches the first read still holds the original after the kubelet replaces the mounted file. TokenReview rejects the cached credential after expiration and the configured clock leeway.
- **Green.** Reopening the file obtains a kubelet-issued token with later expiration before the original expires. The current token still authenticates after the original expires. The Job, Pod, and ServiceAccount identities remain the same.
- **Permitted.** The original token initially authenticates for its named audience. A check for an unrelated audience is rejected.

The case holds token bytes only in process memory and retains sanitized issue and expiration timestamps separately in `rotation-timing.json`. Verify each deployed application reopens its token file and continues to work during refresh. Cloud SDKs, Vault, and training-controller integrations require their own evidence.

[Kubernetes v1.36 service account projection](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#serviceaccount-token-volume-projection) · [v1.36.1 kubelet token manager](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/kubelet/token/token_manager.go)
