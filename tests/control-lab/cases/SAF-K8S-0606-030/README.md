# SAF-K8S-0606-030 GitOps rollout traceability

From the SAF-K8S framework checkout, run with local Docker, Kind, kubectl,
curl and Git.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-030 --docker-context desktop-linux
```

The test reuses the read-only chart source from SAF-K8S-0606-029. Argo CD
deploys two exact commits. For each release the test retains the manifest
Argo CD applied, its digest, the exact Git revision, and the Argo CD history
and Kubernetes rollout evidence. The first record reconstructs a Ready
Deployment in a second namespace while the current revision stays active.

The scope is one chart and one rendered Deployment. Production retention,
other renderers, complete deployed configuration and durable event coverage
require additional evidence.

[Argo CD v3.6.1 deployment history](https://github.com/argoproj/argo-cd/blob/v3.6.1/docs/user-guide/commands/argocd_app_history.md)
