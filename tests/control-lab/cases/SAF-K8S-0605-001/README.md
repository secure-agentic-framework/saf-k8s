# SAF-K8S-0605-001 — Gatekeeper GPU and RuntimeClass admission

```sh
python3 lab.py test SAF-K8S-0605-001 --docker-context desktop-linux
```

From the SAF-K8S checkout, use `python3 tests/control-lab/lab.py`. Each
run uses Kubernetes v1.36.1 and digest-pinned Gatekeeper v3.23.1. The
runner checks the released installer bytes, stages the platform image
into Kind, and installs the case-owned Rego template and constraint.

The pinned Gator CLI checks six cases before policy deployment. The fixture limits total regular-container GPU requests to two and
requires the designated RuntimeClass for a Pod that requests any GPU.
The API accepts the declarations before policy deployment and then
rejects over-budget, wrong-class and missing-class requests. The approved
Pod persists. The policy preserves CPU-only and other-namespace
comparators. The Gatekeeper audit reports an over-budget Pod that existed
before policy deployment.

Both fixture RuntimeClasses map to runc. The test asserts API enforcement
and the stored Pod declaration. Production hardware allocation, runtime
isolation, actual training-controller reconciliation and GitOps rollout
require separate deployment evidence.

See [the pinned SAF control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0605-001.md),
[Gatekeeper usage](https://open-policy-agent.github.io/gatekeeper/website/docs/howto/),
[Gatekeeper audit behavior](https://open-policy-agent.github.io/gatekeeper/website/docs/violations/),
and [the v3.23.1 upstream installer](https://github.com/open-policy-agent/gatekeeper/blob/v3.23.1/deploy/gatekeeper.yaml).

The extended suite checks limits-only Pod admission, ordinary init peaks, and
steady-state accounting for restartable init sidecars. It uses the pinned
Kubeflow Trainer v2.3.0 TrainJob schema and tests the explicit per-node limits
and node counts for the fixture runtime reference through server-side dry runs.
Physical GPU allocation and the training controller require deployment evidence.

The registry from SAF-K8S-0605-002 supplies digest-pinned images signed with
separate fixture keys. Gatekeeper calls the pinned Ratify v1.4.8 external
data provider over HTTPS and requires the approved Cosign signature for
the GPU Pod. The comparison checks wrong-signer admission and provider
unavailability. No Kyverno policies are applied by this fixture.
