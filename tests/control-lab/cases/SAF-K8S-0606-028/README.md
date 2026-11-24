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
fields. Use a disposable test repository for behavior comparisons. The local
Gitea and Flux tests run against separate fixture repositories. An adopter's
evidence links their own protected ref to their own reconciler for the same
revision.

- [Flux source-controller v1.9.1 GitRepository](https://raw.githubusercontent.com/fluxcd/source-controller/v1.9.1/docs/spec/v1/gitrepositories.md)
- [Flux kustomize-controller v1.9.1 Kustomization](https://github.com/fluxcd/kustomize-controller/blob/v1.9.1/docs/spec/v1/kustomizations.md)
- [Argo CD Git verification](https://argo-cd.readthedocs.io/en/stable/user-guide/gpg-verification/)
