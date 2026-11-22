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
