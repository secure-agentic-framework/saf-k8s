# SAF-K8S-0304-012 — Training scratch bounds and ephemeral-storage quotas

The case runs in one disposable Kubernetes v1.36.1 kind namespace. Before
policy activation, the API admits Pods without a scratch size or ephemeral
storage declarations. The namespace-selected admission policy requires
positive `emptyDir.sizeLimit` and storage declarations for regular containers.
A Pod with valid declarations can write and read a tiny marker.

A ResourceQuota accounts for the declared requests and limits of the live
Pod. Two dry-run probes independently exceed the aggregate request or limit
budget. Each rejection names the matching quota key.

A second Pod writes exactly 128 KiB to a disk-backed scratch volume with a
64 KiB limit and verifies its file size. The write succeeds. The kubelet
then evicts the Pod for exceeding that exact volume's size limit. This
demonstrates filesystem-dependent, asynchronous eviction. Actual training
storage behavior, node capacity and monitoring, and deployed policy coverage
require separate evidence.

```sh
python3 lab.py test SAF-K8S-0304-012 --docker-context desktop-linux
```

In the framework repository use `python3 tests/control-lab/lab.py` with the same
arguments.

- [Kubernetes v1.36 local ephemeral storage](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/manage-resources-containers/#local-ephemeral-storage)
- [Kubernetes v1.36 emptyDir](https://v1-36.docs.kubernetes.io/docs/concepts/storage/volumes/#emptydir)
- [Kubernetes v1.36 Resource Quotas](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/)
