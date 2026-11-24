# SAF-K8S-0104-014 recurring scoped CIS scan

Run `python3 tests/control-lab/lab.py test SAF-K8S-0104-014 --docker-context desktop-linux`
from the framework root. The case starts its own digest-pinned Kind v1.34.8
cluster. Use kubectl v1.34.8 for the replay. Aqua kube-bench v0.16.0 maps Kubernetes 1.34 to CIS 1.12. The Jobs
read the disposable node process namespace without host filesystem mounts
or a workload service-account token. The scanner evaluates etcd checks
2.2 and 2.5. The test covers the suspended state, two controller-owned Jobs
scheduled at consecutive UTC minute boundaries, scanner exit status, and
the selected check results from both Jobs.

The production cadence, complete benchmark, managed-service profile coverage,
and scanner compatibility after upgrades remain distinct verification work.

- [Aqua v0.16.0 profile mapping](https://github.com/aquasecurity/kube-bench/blob/v0.16.0/cfg/config.yaml)
- [Aqua CIS 1.12 etcd checks](https://github.com/aquasecurity/kube-bench/blob/v0.16.0/cfg/cis-1.12/etcd.yaml)
- [Kubernetes CronJob behavior](https://v1-34.docs.kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)
- [Kind v0.32.0 image pins](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0)
- [Kubernetes kubectl version skew policy](https://kubernetes.io/releases/version-skew-policy/#kubectl)

## Verify your implementation

1. Inventory the clusters and assessed surfaces. Record the distribution,
   control-plane and node versions, managed provider and mode where relevant,
   node pools, and the responsibility boundary for each benchmark section.
   Use the scanner release's published profile mapping and the provider's
   documented profile for the actual service and mode. Confirm each
   customer-assessable section, including control plane, nodes, and policy,
   is in scope for the recurring automated scans. Route checks the profile
   marks manual to a named evidence workflow with the same cadence. Record
   the basis for excluded provider-owned checks and flag missing automated
   coverage for assessable targets.
2. Record the policy cadence, time zone, maximum acceptable lateness, owner,
   and handling for missed or failed scans and post-upgrade reruns. Inspect the
   approved scheduler and its run history. For a Kubernetes CronJob, use its
   UID, schedule, time zone, suspension state, and start deadline with each
   Job's owner reference, scheduled timestamp where present, and completion
   status. For an external scheduler, use equivalent retained run records.
3. Compare at least two consecutive expected windows with separate completed
   scanner executions. Correlate each receipt with the cluster and relevant
   node identity, scanner build or image digest, benchmark profile, expected
   and observed check IDs, and both Job and scanner result. A completed Job
   with missing targets, incompatible profile, or an empty report leaves
   coverage unverified. A failed benchmark check can still show that the
   assessment ran. Retain failures and manual checks with their disposition.
4. Exercise missed-run and scanner-error reporting in a representative
   sandbox. Confirm the expected notification reaches the assigned owner and
   recovery produces an attributable replacement receipt. After an upgrade,
   check the release mapping and run the applicable profile again. Compare
   the eligible and observed check inventories and explain changed coverage.

- [NIST SP 800-218 v1.1, PW.9.1](https://csrc.nist.gov/pubs/sp/800/218/final) for the separate secure-default baseline design obligation.
