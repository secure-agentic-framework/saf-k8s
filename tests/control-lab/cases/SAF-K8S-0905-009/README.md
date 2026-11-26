# SAF-K8S-0905-009 — Verify model provenance at deployment

From the framework checkout run `python3 tests/control-lab/lab.py test SAF-K8S-0905-009 --docker-context desktop-linux`.

The seven checks use a case-local HTTPS admission verifier with a fixed signed OCI manifest, inert layer and two signed in-toto statements. Before enforcement, an owned Deployment with untrusted metadata is accepted. With the verifier installed, the test observes specific rejections for a wrong digest, changed signature, incorrectly ordered or incomplete material, and a different admitted image digest with otherwise valid statements. The allowed Deployment's verified image reference is read back from the API. The zero-replica workload creates no Pods and the `.test` reference is never pulled.

## Verify deployed provenance

1. Identify approved signer and independent trust roots, provenance and approval authorities, and the required provenance fields for the actual artifact and workload classes. Decide who can change the policy or trust material and record the effective revisions.
2. Verify the digest resolved from the approved registry or artifact source and bind the trust decision to the exact admitted reference. Follow that reference to the consuming runtime or loader and compare the bytes or immutable identity observed there. Cover every enabled deployment update or controller path.
3. Test an approved release and controlled copies for missing or altered signatures and statements, untrusted authorities, and a mismatch between the verified artifact and the actual admitted reference. Confirm failure is attributed to the enforcement decision and retain the source artifact digest, authority, policy and workload identities. Apply and review only approved exceptions.

- [OCI image manifest specification v1.1.1](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md)
- [Kubernetes Deployments](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/deployment/)
