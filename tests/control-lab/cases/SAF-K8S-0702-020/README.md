# SAF-K8S-0702-020 — Namespace ResourceQuota for accelerator workloads

A Kubernetes v1.36.1 kind namespace starts with a limits-prefixed entry for
a synthetic accelerator. The API stores that quota object and still admits
the over-budget dry-run declaration. Replacing it with a requests-prefixed
quota makes the same declaration fail. The NVIDIA GPU resource name uses
the same request accounting. An at-budget accelerator declaration is
admitted only as a dry-run.

The runnable test independently exercises CPU and memory request and limit
quotas, PVC storage requests, and Pod, PVC and Service counts. It leaves one
bounded Pod Ready. Accelerator scheduling, device health, scope selectors,
and policy rollout across training namespaces require separate evidence.

```sh
python3 lab.py test SAF-K8S-0702-020 --docker-context desktop-linux
```

From the framework checkout use `python3 tests/control-lab/lab.py` with the
same arguments.

- [Kubernetes v1.36 ResourceQuota](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/#quota-for-extended-resources)
- [Kubernetes v1.36 GPU device resources](https://v1-36.docs.kubernetes.io/docs/tasks/manage-gpus/scheduling-gpus/)
