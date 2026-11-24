# SAF-K8S-0606-028 trusted GitOps source signatures

From the SAF-K8S framework checkout, run with local Docker, Kind, kubectl,
Git, GnuPG and curl.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-028 --docker-context desktop-linux
```

Flux v2.9.0 reads case-owned repositories through a read-only Git Smart HTTP
service. A fixture key signs one commit, and a second fixture key signs another.
Flux accepts the trusted commit and deploys its exact revision. The same
unsigned branch is tested with and without HEAD verification in separate
reconciliations. With verification enabled, unsigned and untrusted commits
must fail before Flux creates a source artifact or applies their markers.

The local Gitea 1.23.8 companion uses a private synthetic repository and an
owned loopback-only forward. It reads back both protected rules, tests
unsigned and signed writes, checks distinct missing-status and missing-review
denials, and reads back the verified signed PR head after fast-forward
promotion. Git identities, keys and credentials are disposable. Hosted Git
policy, trusted key custody and exception handling require deployed evidence.

The additive `saf-lab-0606-028.3` path keeps these checks and the unsigned Flux
contrast. It installs the pinned Flux controllers once with in-cluster status
and events, and omits forwarding to a notification service. It serves the same owned
private Gitea repository through a ClusterIP Service to a `GitRepository` and
`Kustomization`. A separate synthetic collaborator has repository read access
and a token scoped to repository reads; Flux receives that credential and the
writer's public trust key through private stdin to `kubectl`, with subprocess
output discarded. No private value is included in evidence, logs, tracked
files, or this README.

Flux first applies the signed protected-ref baseline. The harness then requests
a fresh source and Kustomization reconcile after each existing Gitea denial
(unsigned signature, signed direct push, missing status, and missing approval).
Each checkpoint compares the exact protected ref, source artifact revision and
digest, applied revision, and inert ConfigMap marker with the baseline. The
fully gated signed fast-forward promotion must move all three revision views to
the same new commit and apply a different inert marker. The additive sanitized
receipt is `gitea-flux-correlation.json`; the pre-existing Gitea receipt remains
`gitea-branch-observations.json`.

This extension uses only the case-owned Gitea instance, its private fixture
repository, and the existing pinned Flux controllers in the disposable lab
cluster. It does not assess hosted policy or production repositories.

Flux HEAD verification covers the selected commit. Assess historical commits
against the repository's signed-commit requirements.

[Gitea 1.23 branch protection API](https://docs.gitea.com/api/1.23/operations/repo-create-branch-protection/)
[Flux source-controller v1.9.1 GitRepository documentation](https://github.com/fluxcd/source-controller/blob/v1.9.1/docs/spec/v1/gitrepositories.md)

## Verify your implementation

Trace each deployment's configured source to its exact host, repository,
protected branch and path. Read the effective rules, including inherited rules
and exceptions. Retain allowed writers and administrative bypass identities,
signed-commit requirements, minimum independent approvals, and the exact
identity and result of each required check. Bind each approval and check to
the relevant PR head. When a merge creates a different commit, record its
relationship to the reviewed head and verify the signing policy that applies
to the resulting protected-ref commit.

Retain the full protected-ref commit ID, signature verification result and
signer fingerprint. Check signer eligibility against the approved key inventory,
including ownership, expiry, rotation and revocation. Retain the exception
owner, approvals, expiry and logged use. A provider's signature result covers
cryptographic verification. The key inventory supplies the ownership and
authorization evidence.

For Flux, read the named source and Kustomization in the approved context.
The reference case checks the source reference, verification mode, artifact
commit and applied commit.

```sh
kubectl --context "$SAF_CONTEXT" -n "$SAF_SOURCE_NS" get gitrepositories.source.toolkit.fluxcd.io "$SAF_SOURCE" -o json
kubectl --context "$SAF_CONTEXT" -n "$SAF_APPLY_NS" get kustomizations.kustomize.toolkit.fluxcd.io "$SAF_APPLY" -o json
```

Verify that the Kustomization's `spec.sourceRef` and path select that source.
Check the successful `SourceVerified` condition, both Ready conditions, and
the observed generations against the current specs. Compare the protected Git
ref's full commit ID with the GitRepository's `status.artifact.revision` and
the Kustomization's `status.lastAppliedRevision`. Use the applied revision for
this comparison. Repeat the collection if the ref moves during capture.
For Argo CD, use the installed version's Git source integrity policy and the
Application's successful sync result for the corresponding source and revision.

Record the evidence time, scope, revisions, observed results and any unavailable
fields. Use a disposable test repository for behavior comparisons. The reference includes both independent checks and a replay in which
Flux consumes the same protected Gitea branch. An adopter can use that
comparison to link their protected ref and applied revision.

- [Flux source-controller v1.9.1 GitRepository](https://raw.githubusercontent.com/fluxcd/source-controller/v1.9.1/docs/spec/v1/gitrepositories.md)
- [Flux kustomize-controller v1.9.1 Kustomization](https://github.com/fluxcd/kustomize-controller/blob/v1.9.1/docs/spec/v1/kustomizations.md)
- [Argo CD Git verification](https://argo-cd.readthedocs.io/en/stable/user-guide/gpg-verification/)
