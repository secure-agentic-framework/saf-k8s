# SAF-K8S-0702-031 — Production promotion classification gate

```sh
python3 lab.py test SAF-K8S-0702-031 --docker-context desktop-linux
```

The catalog requires promotion or production deployment to be blocked when
classification metadata is absent, invalid, or not validated for the target
environment. The namespace-scoped `ValidatingAdmissionPolicy` checks CREATE
and UPDATE requests for synthetic Deployments against a separate approval
ConfigMap supplied by the lab administrator. The ConfigMap records the approved
classification, target, policy version and SHA-256 digest for an inert fixture.
The baseline API dry-runs accept each invalid declaration. With the gate
installed, the same dry-runs are rejected, the independently approved record
is persisted on a Deployment, and removing target validation on UPDATE is
rejected. An unenrolled namespace demonstrates the binding's scope.

Admission verifies the declared digest against the independently supplied
fixture reference. Actual registry content verification, signers, artifact
approval, protection of the approval record, production CI/CD enforcement,
and namespace enrollment require deployment evidence.

- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes v1.36 ValidatingAdmissionPolicy API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/admissionregistration/validating-admission-policy-v1/)

## Verify the adopted promotion routes

1. Inventory all promotion and deployment routes, including CI jobs,
   registries, approved manual procedures, rollout controllers and recovery
   or rollback. Record target enrollment, label ownership and the responsible
   approval system.
2. Protect the authoritative classification and approval record. Bind the
   exact reviewed artifact digest, policy revision and destination, and
   retain the approval issuer, timestamp and integrity evidence. Confirm
   that an ordinary submitter cannot alter the classification or enrollment
   independently.
3. Before adopting the control, apply the same approved benign comparisons
   to the actual pipeline and deployment controls. Compare missing, invalid,
   older policy, wrong-target and mismatched-digest metadata with the fully
   approved request. Independently verify failed operations persist no
   deployment and allowed operations retain the exact reviewed metadata.
4. Verify actual artifact provenance upstream and bind it to the same
   promotion decision. [SAF-K8S-0905-005 demonstrates approved and refused signed evidence](https://github.com/secure-agentic-framework/saf-k8s/blob/8bf699c01f7b1c8f77293f7444c7a0bb5baa2dd6/tests/control-lab/cases/SAF-K8S-0905-005/README.md).
   Preserve signer and approval changes under the effective protection at each
   authorized promotion route.
5. Confirm the exact destination through independent registry and workload
   readback, compare the classification and allowed digest, and retain
   rejection, success and reviewed exception records. Repeat the evidence
   checks after policy, signers, pipeline or target enrollment changes.
