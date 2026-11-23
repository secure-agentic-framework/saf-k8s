# SAF-K8S-0402-014 — Ephemeral training job credential revocation on completion

From the framework repository, run:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0402-014 --docker-context desktop-linux
```

The run issues short-lived, synthetic TokenRequest credentials bound to individual Job Pods in a fresh Kubernetes v1.36.1 cluster. It uses an explicit audience and the Kubernetes TokenReview endpoint. Token bytes stay in process memory.

- **Red.** With no finished-Job TTL, Jobs that succeed and fail retain their Pods. Their bound credentials keep authenticating after each terminal condition while expiration is still in the future.
- **Green.** A second success and failure pair set `ttlSecondsAfterFinished: 12`. The controller observes each terminal Job, deletes the Job and dependent Pod, and the original credential fails TokenReview while its encoded expiry remains more than five minutes away.
- **Permitted.** An unrelated active Pod identity authenticates before and after the cleanup.

A finalizer can hold deletion while an explicit controller completes its work. Verify the dependent Pod is removed and the relying party rejects the credential. External systems doing offline JWT verification and deployed Vault or cloud credentials need separate cleanup evidence.

[Kubernetes v1.36 Job cleanup](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/#clean-up-finished-jobs-automatically) · [Kubernetes v1.36 bound token validation](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/) · [Kubernetes v1.36 finalizers](https://v1-36.docs.kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/)
