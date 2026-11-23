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
