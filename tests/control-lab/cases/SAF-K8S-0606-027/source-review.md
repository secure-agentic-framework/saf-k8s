# SAF-K8S-0606-027 source review

The original catalog at revision 133a8698a45e2b335b51728bf4c62f7bda98d15f
requires repository access restrictions and deploy credentials scoped to the
permissions the GitOps system needs. Gitea distinguishes repository deploy
keys with read-only access from individual collaborator permissions.
[Gitea deploy-key API](https://docs.gitea.com/api/1.23/operations/repo-create-key/)
[Gitea permission configuration](https://docs.gitea.com/1.23/usage/permissions/)

The fixture toggles the grant on the same public key, checks actual Git
operations and exact remote refs, and verifies an independent write
comparison. It covers two private fixture repositories on this Gitea
version. Production credential issuance, owner and workload permissions,
renewal, branch rules, and repository coverage require deployed evidence.
