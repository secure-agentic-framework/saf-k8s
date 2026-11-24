# SAF-K8S-0910-026 admission baseline federation

Run `python3 lab.py test SAF-K8S-0910-026` from the control-lab directory.

The same approved policy bytes are pinned by SHA-256 and checked against the
immutable approval ConfigMap in each of two separately owned API servers.
The case checks that a candidate identity cannot change the approval or the
active native policy. Both API servers admit the synthetic Deployment in
server-side dry run before policy. Once the policy and binding are installed,
both deny the same Deployment with the policy's exact message and continue
to admit a compliant request.

The example exercises one admission policy bundle and the observed API
decisions. Production rollout authority, approval, and coverage across other
policy types require separate deployment evidence.

- [Kubernetes ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes dry run](https://kubernetes.io/docs/reference/using-api/api-concepts/#dry-run)
