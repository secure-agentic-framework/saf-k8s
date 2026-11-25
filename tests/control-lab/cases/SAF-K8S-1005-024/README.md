# SAF-K8S-1005-024 — Inference quarantine and pipeline suspension

Run through the SAF-K8S control lab with Docker, Kind and kubectl available to
the supervisor:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1005-024 --docker-context desktop-linux
```

The case uses the framework's fresh, disposable Kubernetes v1.36.1 Kind cluster
and its `saf-test` namespace. All workload and incident metadata is synthetic.
The two HTTP Deployments use a digest-pinned Docker Official Python image. They
serve fixed JSON markers over ClusterIP Services; neither makes external
requests. A separate native Kubernetes Job runs only a Python sleep loop. It is
created active so the baseline is observable, then suspended through
`spec.suspend`. An immutable ConfigMap holds short, inert fixture bytes as
`binaryData`; no Secret objects, model material, feed data, target data, or
credentials are used.

## Observations

- **Red baseline:** before containment, an in-cluster request reaches the mock
  inference Service and the native Job has an active Pod.
- **Green containment:** the exact mock inference Deployment is scaled to zero;
  the case waits for its observed generation, zero available replicas, no
  remaining selected Pods, and no ready EndpointSlice addresses. A request to
  that Service then fails. The native Job has `spec.suspend: true`, a true
  `Suspended` condition, and no remaining selected Pods.
- **Green evidence fixture:** the case reads the immutable checkpoint ConfigMap
  before and after containment, decodes the raw bytes and compares them
  byte-for-byte and by SHA-256.
- **Positive comparator:** a request to the separate healthy fixture Service
  still returns its expected synthetic marker and it retains a ready endpoint.

The runner writes its standard per-check JSON and command transcript plus
`containment-observations.raw.json`, which contains raw API JSON readbacks and
request summaries for these synthetic fixtures. It contains no Secret data or
credential material. The supervisor should inspect the two run results and
their evidence independently; this draft has not run Docker or Kubernetes.

## Control review and limits

Kubernetes documents that scaling a Deployment changes desired Pod count and
that the Deployment selector targets its Pods. It documents that a Job created
or updated with `spec.suspend: true` will not create work Pods and that active
Pods are terminated on suspension, with graceful termination delegated to the
workload. These sources support the API mechanics
exercised here. They do not prescribe the control's organization-level,
AI-specific response procedure or show that a selected containment action is
safe for a real model endpoint or training pipeline.

The checkpoint object is a separate immutable fixture. Its unchanged bytes show
only that this ConfigMap remained readable and unchanged during this run. They
do not establish that a real training process checkpointed coherently, that an
in-progress training Job preserved its memory or external state, or that
evidence storage is durable or tamper-resistant. The control rationale's
customer-impact and state-loss risks are unmeasured here. Kubernetes notes that
suspending a running Job terminates its active Pods; workload-specific graceful
state capture is outside this mock.

The case does not test Argo or any other ML pipeline controller, controller
reconciliation races, HPA or GitOps interference, admission and authorization,
traffic from outside the cluster, customer impact, rollback, recovery, real
incident authority or communications, service-specific drain behavior, or
production state safety. The control's requirement to define and document
AI-specific procedures remains an organizational evidence claim, not something
this mechanics fixture can prove. Kubernetes API references do not validate
that wider obligation.

## Primary sources

- [Kubernetes v1.36 Deployments: scaling and selectors](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/deployment/)
- [Kubernetes v1.36 Jobs: suspending a Job](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/#suspending-a-job)
- [Kubernetes v1.36 Job API: `spec.suspend`](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/batch/job-v1/)
- [Kubernetes v1.36 Services: selector-based routing and EndpointSlices](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/service/)
- [Kind v0.32.0 release: Kubernetes v1.36.1 node image digest](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0)
- [Docker Official Python 3.13 slim image digest](https://hub.docker.com/layers/library/python/3.13-slim?tab=layers)

The training Pod reads the mounted checkpoint before suspension. The healthy fixture reads
the same immutable checkpoint after containment, and the case checks both digests against
the bytes and object identity returned by the API.

## Verify an adopting implementation

Map inference endpoints, orchestration controllers,
stateful jobs, checkpoint dependencies, and independent services. In an
approved production-equivalent drill, quarantine the affected route, suspend
the actual workflow safely, and validate checkpoint consistency and restore
with application owners. Verify independent service health and record
customer-impact boundaries, approval, measured timing, rollback, and recovery
signoff.
