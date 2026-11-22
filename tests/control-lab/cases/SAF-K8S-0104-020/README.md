# SAF-K8S-0104-020 — Kubernetes supported version window compliance

The case evaluates a dated snapshot of upstream minor-release schedules and
patch listings. With the check disabled, the end-of-life case goes unevaluated.
With the check enabled, the same version is rejected on its end-of-life date.
Other fixtures cover the first release date, limited maintenance, an older
patch in an active series, and a patch outside the recorded snapshot.

The runner reads the actual API server and kubelet versions from disposable
kind and evaluates them against the reference date. The decision establishes
eligibility for upstream branch support as of that reference. Use current
upstream and provider schedules for real deployments. Patch currency and
completed upgrade evidence remain separate.

```sh
python3 lab.py test SAF-K8S-0104-020 --docker-context desktop-linux
```

From the framework checkout use `python3 tests/control-lab/lab.py` with the
same arguments.

- [Pinned SAF-K8S control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0104-020.md)
- [Kubernetes patch release support periods](https://kubernetes.io/releases/patch-releases/)
- [Kubernetes release history](https://kubernetes.io/releases/)
