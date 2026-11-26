# SAF-K8S-0905-009 — Verify model provenance at deployment

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-009 --docker-context desktop-linux` from the framework checkout.

A case-local HTTPS admission verifier checks the exact signed manifest, inert layer
and two in-toto statements. The initial comparison admits an owned Deployment with
untrusted metadata before enforcement. With verification enabled, the API refuses
missing and changed evidence, incorrectly ordered statements, and a different image
digest. It persists the approved Deployment with the exact digest reference.

The verifier also covers the selected Deployment UPDATE path. Removing the
required signature is refused. An approved metadata update preserves the
same Deployment, full signature and digest reference.

After readback, the fixture publishes the exact inert OCI bytes to its temporary
TLS registry. A separate non-root Job retrieves the manifest and layer by digest
over verified TLS, reads the fixed bytes and reports only digests and outcomes.
The protected Deployment has zero replicas. The independent reader demonstrates
the authorized fixture handoff and the exact artifact data path.

For adoption, inventory the real artifact source, approved trust and signer
authorities, required provenance stages, governed workloads, and CREATE and UPDATE
paths. Verify that the actual runtime consumes the same immutable artifact the
admission decision approved. Exercise exact approved and mismatched references,
missing evidence and invalid signatures on every governed path. Retain the
decision, identity, source and loader references, policy revision and alerts.

- [OCI image manifest v1.1.1](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md)
- [Kubernetes v1.36 admission control](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- [Kubernetes v1.36 Jobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/)
