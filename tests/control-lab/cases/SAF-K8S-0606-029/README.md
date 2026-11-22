# SAF-K8S-0606-029 GitOps release metadata

Run from the lab root.

```sh
python3 lab.py test SAF-K8S-0606-029 --docker-context desktop-linux
```

Argo CD deploys two exact Git commits containing successive versions of a
fixture Helm chart. Before recording either version, the test observes the
resolved Argo CD revision, version on the Deployment and Ready Pod, and the
Pod runtime image digest. It checks that Argo CD's manifest rendering produces
a live workload without a Helm release Secret.

The runner writes an immutable release record for each version and reads both
back after promotion. Each record binds the package version to the source chart
tree, the observed workload image and the exact Kind cluster and namespace.
A write check verifies that Kubernetes refuses to change the earlier record.
The complete per-cluster records also appear in local run evidence.

This models retaining source chart and deployment identities. Registry
package digests, production retention and access policy, automation and
inventory coverage require separate evidence.

[Argo CD 3.6.1 Helm documentation](https://github.com/argoproj/argo-cd/blob/v3.6.1/docs/user-guide/helm.md)
