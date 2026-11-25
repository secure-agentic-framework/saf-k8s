# SAF-K8S-0702-027 Pipeline label application and propagation

```sh
python3 lab.py test SAF-K8S-0702-027 --docker-context desktop-linux
```

The [catalog control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0702-027.md)
requires pipeline labels to be applied, propagated and checked periodically.
In kind v1.36.1, the Job controller selects the Pod template when it creates
a child. Both inert Jobs complete. Labeling the Job metadata leaves its
child unlabeled. Labeling the template carries the expected classification
to the owned Pod.

The corrected fixture inventory checks the Job, Pod, PVC, Service, and
ConfigMap directly. A label-selector query includes the labeled parent and
omits its unlabeled child. Periodic production verification needs an
independent inventory of expected resources and deployed orchestration
evidence across execution and storage stages.

- [Tagged Kubernetes v1.36.1 Job controller](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/controller/job/job_controller.go#L1768-L1772)
- [Kubernetes v1.36 Jobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/)

## Adopter verification

1. Inventory the actual pipeline stage APIs, expected owned Jobs, Pods,
   artifacts and storage references from an independent source.
2. Check stage labels in the exact submitted workload templates and in
   their generated child resources. Reconcile label ownership and
   drift using the selected controllers and namespaces.
3. Compare selector-based discovery with the expected full inventory.
   Verify that missing, misplaced or conflicting labels produce a finding.
4. Record every stage, artifact and exception with the responsible
   owner, periodic review cadence and evidence source.
