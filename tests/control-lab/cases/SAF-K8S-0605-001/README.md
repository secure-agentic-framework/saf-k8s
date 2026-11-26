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

## Verify the adopted policy

1. Inventory the Kubernetes and Gatekeeper versions, matching namespaces and
   workload kinds, deployed webhook settings, policy templates and constraints,
   and approved exceptions. Record the versions and policy release revision
   together. Identify the effective GPU resource names, quota, approved
   RuntimeClasses and runtime or device-plugin versions.
2. Run Gator tests at the exact proposed Git revision. Include the allowed
   workload, boundary values, wrong or missing runtime class, effective limit
   defaults, init and sidecar accounting, and an out-of-scope comparator.
   Apply the proposal to a disposable environment with matching versions.
   Compare server-side admission before and after applying the policy and
   verify both the approved object's state and the exact denial reason. Run
   each installed training CRD through the same checks and inspect the Pod
   produced by the real controller.
3. Submit a harmless nonconforming workload before applying the policy.
   Confirm the Gatekeeper audit identifies the existing object and exact
   violation. Record ownership, approved exceptions and the disposition.
4. With an owned registry and the approved verification chain, compare an
   approved signed digest, a digest signed by another fixture key, and an
   unsigned digest. Temporarily remove the test verifier endpoint from the
   disposable deployment. Confirm the affected workload is refused while
   Gatekeeper stays available. Restore the verifier and verify that the
   approved digest is accepted again. Check signer rotation, trust configuration
   and independent inventory in the adopted environment.
5. Require the approved test results on the exact policy revision before
   protected Git promotion. Verify the promoted commit matches the deployed
   policy and that ordinary contributors cannot bypass approval. Retain the
   test results, rule decisions, exception register and change records.
   [SAF-K8S-0606-024 verifies the protected-ref comparison](https://github.com/secure-agentic-framework/saf-k8s/blob/83c0ba792c56d925793aa8ee2a5acf9b58b2654f/tests/control-lab/cases/SAF-K8S-0606-024/README.md).

The executable case checks the Gatekeeper, Gator, Ratify and API assertions
with disposable repositories and fixture signing keys. The two RuntimeClass
names share the runc handler and the extended TrainJob checks use server-side
dry run. Verify hardware allocation, runtime isolation and real generated
workloads on each adopter's supported platform.
