# SAF-K8S-0702-016 — Classification across promotion and serving

```sh
python3 lab.py test SAF-K8S-0702-016 --docker-context desktop-linux
```

The local promotion command verifies the content digest and the approved
classification before each development-to-staging and staging-to-production
transition. It carries the same small public payload to each stage and emits
the approved classification and digest in the serving Deployment template.
Each transition rejects removed or changed classification and substituted
payload bytes. Rejections leave no promotion outputs.

A namespace-scoped Kubernetes admission policy rejects missing or changed
classification and a changed digest on Deployment CREATE. A permitted
Deployment rolls out, and its Pod retains the approved template metadata.
A separate UPDATE dry-run verifies that admission also rejects digest drift
after the Deployment exists.

The case contains no actual model or training data. Production registry
integration, policy approval, signed provenance and authorized reclassification
require separate evidence. The runner removes the temporary outputs and
disposable cluster.

- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [OCI Image Manifest 1.1.1](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md)

## Adopter verification

1. Inventory actual development, staging and production paths, registry
   and artifact IDs, promotion authorities and recorded classifications.
2. Verify preservation of approved classification and immutable digests
   across each edge. Rehearse rejection of missing or mismatched metadata
   under the selected pipeline.
3. Verify the deployed serving reference and workload template metadata,
   and check the applicable create and update decisions.
4. Retain authorized reclassification, immutable lineage and audit
   evidence for every applicable promotion and serving path.
