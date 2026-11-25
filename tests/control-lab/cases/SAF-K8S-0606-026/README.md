# SAF-K8S-0606-026 — Gate promotion on measured repository posture

```sh
python3 lab.py test SAF-K8S-0606-026 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py`.
The test requires host Git and a Docker-backed Kind Kubernetes v1.36.1
cluster. OpenSSF Scorecard v5.6.0 runs in the cluster and evaluates the
`Pinned-Dependencies` check against two detached Git checkouts. The scanner
reads the exact checkout without executing its workflow. The test records
the actual Git revision and a workflow digest alongside the scanner output.
The local-mode report identifies the checkout directory and reports an
unknown revision, so the checked-out Git revision is verified separately.

A native Kubernetes admission policy protects an inert release marker. The
policy takes the gate-owned assessment list as a read-only input and requires
a passing score for the exact repository and Git revision. It denies a weak
score, an unassessed revision, and an attempt to use the approved revision
under a different repository identity. Each denial preserves the existing
marker. The passing revision updates it. The cutoff of eight is specific to
this fixture.

The [pinned control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0606-026.md)
also requires recurring assessment and wider hosted SCM posture. Hosted
branch protection depends on forge features and, for some settings, elevated
read permissions. Those checks, checker trust custody, production exclusions,
and real release coverage require independent evidence.
See [Scorecard v5.6.0 checks](https://github.com/ossf/scorecard/blob/v5.6.0/docs/checks.md),
[GitHub guidance on pinning actions](https://docs.github.com/en/actions/reference/security/secure-use#using-third-party-actions),
and [Kubernetes v1.36 admission policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/).

## Verify an adopting implementation

Map the actual hosted SCM organization/repositories,
scheduled assessment identities, protected workflow permissions, evidence
freshness, and authorized source of results. Verify all promotion paths
require the intended repository and current assessed revision and preserve the
prior release on missing, stale, or failing posture evidence. Retain coverage
for branches, workflow variants, and exceptions.
