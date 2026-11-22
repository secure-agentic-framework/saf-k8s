# SAF-K8S-0606-027 GitOps repository credential scope

Run from the SAF-K8S framework checkout with Git, OpenSSH and the Kind prerequisites.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-027 --docker-context desktop-linux
```

The test starts an isolated Gitea 1.23.8 instance, creates two private
fixture repositories, and creates a disposable SSH deploy key. The same
key writes a fixture branch with a writable grant. Changing it to
read-only preserves access to the known commit and denies the next branch
creation. The test verifies that the denied ref is absent. The key also
cannot read the separate private fixture repository. A separate account
with the approved maintenance role writes its own inert change.

Git and API calls use loopback forwarding to the owned Kind Pod. The
runner retains commit, digest, grant and denial evidence. Fixture
credentials are transient. Production repositories, branch protection,
deploy credential storage, rotation and rollout need separate evidence.

- [Gitea 1.23 deploy keys](https://docs.gitea.com/api/1.23/operations/repo-create-key/)
- [Gitea 1.23 repository permissions](https://docs.gitea.com/1.23/usage/permissions/)
