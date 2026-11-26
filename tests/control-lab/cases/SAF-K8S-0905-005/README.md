# SAF-K8S-0905-005 — Enforce model promotion evidence and signer trust

Run from the lab checkout.

```sh
python3 lab.py test SAF-K8S-0905-005 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py`.
The case runs two separately configured gate copies in owned Kubernetes.
It uses fixed synthetic model and evaluator records. The disabled comparison
accepts a failing result. The enabled copy uses the real Kubernetes TokenReview
API to validate the fixture audience and approved reporting ServiceAccount.
The gate checks the exact records for security, bias, performance and
robustness, verifies artifact and predicate digests, and reads back its
persisted evidence after the authorized request.

A separate short-lived Pod uses the pinned OpenSSL 3 implementation to generate
fixture Ed25519 keys and sign canonical evidence. Only public keys and the
synthetic signatures leave that process. The gate uses a separately mounted
immutable public-key pin. The approved signature allows the complete decision.
An unrelated key and changed signed evidence both cause refusal before the
evidence ConfigMap changes.

The fixed evaluator records exercise the enforcement point. Validation of
actual test metrics, model behavior, protected producer attribution and
production promotion coupling uses the adopted system's evidence.

## Verify the adopted promotion path

1. Enumerate all model artifacts, registries, CI/CD jobs, rollout controllers
   and exception paths. Determine which operation can authorize a promotion
   and how the observed gate decision controls that operation.
2. Define the appropriate test suite, representative test data and expected
   thresholds before review. Measure the actual artifacts and bind each report
   to the exact model bytes, monitored source revision, evaluator version and
   approved producing identity.
3. Use approved key custody and trust pins. In a disposable representative
   environment, verify an approved signer, unrelated signer, changed envelope,
   missing evidence and failing test result. Confirm persistent state and the
   independent deployment receiver both reflect the decision. Exercise needed
   key rotation, expiry, revocation and verifier loss.
4. Check the separately approved test and human review workflow, deployment
   authorization and scope of any exceptions. Retain decisions, approved
   metrics and provenance with the corresponding exact promoted artifact.

[Kubernetes TokenReview](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/)
and [EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng).
