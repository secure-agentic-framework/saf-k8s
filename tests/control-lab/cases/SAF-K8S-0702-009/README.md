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

## Controller scope and adopter evidence

The independent runs cover the four configured resource kinds. With the policy active, the selected namespace admits the approved Job and StatefulSet templates, and the unselected namespace admits unlabeled Job, Deployment, and StatefulSet templates. These comparisons are server-side dry runs. The existing Deployment positive case independently observes a Ready Pod with the approved labels.

In adoption, use the effective classification keys and values from SAF-K8S-0702-005. Record how namespaces are selected and who may change their labels. Verify permitted and denied CREATE and UPDATE decisions for each covered kind in selected namespaces and demonstrate non-enrolled behavior. Test separately where parent metadata is required by the selected schema. Record treatment of existing objects, workload paths and authorized exceptions before applying the policy to the intended scope.
