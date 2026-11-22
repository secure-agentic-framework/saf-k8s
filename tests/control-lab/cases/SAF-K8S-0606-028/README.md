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

The fixture uses ephemeral signing keys. Repository rules, checks and pull
request approvals require separate evidence from the Git host. Flux HEAD
verification covers the selected commit. Assess historical commits against
the repository's signed-commit requirements.

[Flux source-controller v1.9.1 GitRepository documentation](https://github.com/fluxcd/source-controller/blob/v1.9.1/docs/spec/v1/gitrepositories.md)
