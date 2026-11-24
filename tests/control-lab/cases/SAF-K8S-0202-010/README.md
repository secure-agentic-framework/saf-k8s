# SAF-K8S-0202-010 node seccomp default

Run `python3 tests/control-lab/lab.py test SAF-K8S-0202-010 --docker-context desktop-linux`
from the framework root.

An inert Linux Pod runs on the disposable Kind worker with kubelet
`seccompDefault` disabled, then a fresh Pod runs with it enabled. Process
status observes the effective filter mode. The scoped admission policy
rejects explicit `Unconfined` at Pod and container level. Both negative
requests and the documented fixture namespace exception use server dry
runs. An explicitly declared `RuntimeDefault` Pod then runs under the policy.

Deployed exception approvals, broader node/runtime coverage and independent
AppArmor or SELinux posture remain unverified.

- [Kubernetes v1.36 seccomp defaults](https://v1-36.docs.kubernetes.io/docs/tutorials/security/seccomp/)
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)

## Verify your implementation

1. List the supported Linux node pools and record the Kubernetes, kernel,
   runtime name and version, node image, and owner-approved baseline. Check
   the loaded kubelet configuration by node, using an approved export or
   provider evidence where the live endpoint is unavailable.
2. Where authorized, read the effective value with the named node and context.

   ```sh
   kubectl --context "$SAF_CONTEXT" get --raw "/api/v1/nodes/$SAF_NODE/proxy/configz" \
     | jq -e '.kubeletconfig.seccompDefault'
   ```

3. Compare fresh disposable Pods with no profile and an explicit approved
   profile. Inspect the admitted Pod and container security contexts and
   corroborate the filter on the running Linux process. In the reference test,
   the omitted profile changes from mode 0 to mode 2 after enabling the
   kubelet default, and the existing process remains in its previous mode.
   Compare behavior per node pool and runtime. Mode 2 shows a filter; use a
   workload-safe comparison to assess the intended syscall policy.
4. Read back the active admission policy and its match scope. Compare allowed
   and denied explicit overrides in a disposable namespace. Retain the owner,
   expiry, scope and compensating measures for an exception. Retire it and
   verify the same unapproved request is denied while the approved request
   passes. Review privileged-workload admission separately because privileged
   containers run Unconfined. Plan replacement of earlier workloads and confirm their new
   processes use the expected filter.
5. Retain the configuration version, node and Pod identity, filter status,
   policy decision, and lifecycle evidence. Record AppArmor or SELinux evidence
   under the applicable controls and call out any unsupported node pool.

- [Kubernetes v1.36 kubelet configuration](https://v1-36.docs.kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/)
