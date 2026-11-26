# SAF-K8S-0402-013 — Credential rotation in a continuing Job

Run from the lab checkout.

```sh
python3 lab.py test SAF-K8S-0402-013 --docker-context desktop-linux
```

From the framework checkout, invoke `python3 tests/control-lab/lab.py`.
The disposable Job mounts an explicit 600-second projected credential
for one synthetic audience. Its unprivileged client reopens the file while
the same Pod and ServiceAccount stay active. A private observer verifies
that the client saw the same replacement read independently by the test.
The Kubernetes TokenReview API authenticates the live credential for its
intended audience and refuses the unrelated one. The result retains only
the observed predicates.

The cached initial credential continues to refer to the old value. The
file-based client observes its replacement before the initial expiry.
After the fixture's expiry and leeway window, Kubernetes refuses the
cached credential and still accepts the current one for the same Pod
identity. This case takes about 12 minutes because it waits for the actual
credential lifecycle.

## Verify the adopted credential path

1. Identify each training or pipeline workload, accepting service,
   issuer, audience, credential lifetime, expected job duration and
   permitted scopes. Verify actual Kubernetes projection, Vault lease
   semantics or cloud SDK refresh as applicable to each workload.
2. Observe the continuing real client obtaining the replacement before
   the previous credential becomes unusable. Compare a client with
   refreshed credentials and a deliberately stale cached fixture. Verify
   the accepted requests and expected denial independently through the
   actual accepting service.
3. Exercise an approved refresh failure and recovery scenario. Measure
   the retry and expiry window, verify the workload's approved failure
   behavior and resume access after authority recovery. Keep actual
   Job and Pod ownership and controller behavior in the evidence.
4. Retain audience, expiry and replacement observations, the effective
   policy, actual identity continuity, issuer and client versions and
   recovery outcomes without raw credentials or fingerprints.

[Kubernetes service account token projection](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
and [TokenReview](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/).
