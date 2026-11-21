# SAF-K8S-0702-009 — Workload classification admission

```sh
python3 lab.py test SAF-K8S-0702-009 --docker-context desktop-linux
```

A namespace label binds native Kubernetes CEL policies to Pods and to Pod
templates on Deployments, StatefulSets, and Jobs. The fixture enforces the
three minimum workload type, data sensitivity and model tier classifications
from SAF-K8S-0702-005. Additional organizational schema rules, controller
parent metadata requirements, and trusted enrollment or exception management
need separate evidence.

The control-off arm verifies that the API accepts both missing and disallowed
classifications on CREATE and accepts a wrong-value UPDATE for each kind.
The fixture Job is suspended so its template labels are mutable on the tested
version. After policy activation, the same requests receive the exact policy
denial. An out-of-scope namespace still admits its fixture. A valid Deployment
rolls out to a Ready Pod and retains all three classifications. The runner
deletes the isolated cluster and all test objects.

- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes v1.36 Jobs and mutable scheduling directives](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/#mutable-scheduling-directives)
