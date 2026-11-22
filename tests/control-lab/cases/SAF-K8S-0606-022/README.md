# SAF-K8S-0606-022 — Verify ConfigMap signatures at admission

```sh
python3 lab.py test SAF-K8S-0606-022 --docker-context desktop-linux
```

From the SAF-K8S framework checkout, use `python3 tests/control-lab/lab.py`.
The case requires host Go and a Docker-backed Kind cluster. It builds a
standard-library HTTPS webhook and generates ephemeral signing and TLS keys
for each run. The signing keys stay in memory. The TLS key is written only
into the runner's temporary directory, imported into the disposable cluster,
and removed from the host. Evidence retains only public certificates,
signatures, signed preimages, and relevant admission decisions.

Before registering the webhook the API stores the unsigned fixture. After
registration the webhook rejects absent signatures, an otherwise valid
signature from an unapproved signer, and changed binary data. It accepts
the unchanged authorized fixture. It also rejects an update with an old
signature, leaves the stored resource unchanged, and accepts the exact
payload after re-signing.

The signed JSON includes API version, kind, name, namespace, labels, data,
binary data, and the optional immutable field. Server-managed metadata,
other metadata, and original file formatting are outside the projection.
Kubernetes sends the API object in a JSON AdmissionReview. This test
exercises the selected ConfigMap CREATE and UPDATE paths. The wider catalog
obligations include other kinds and namespaces, policy ownership, signer
governance, and coverage of actual GitOps and deployment automation.

See [the pinned control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0606-022.md),
[Kubernetes v1.36 validating webhooks](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/),
and the [v1.36.1 admission types](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/api/admission/v1/types.go).
