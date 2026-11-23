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
