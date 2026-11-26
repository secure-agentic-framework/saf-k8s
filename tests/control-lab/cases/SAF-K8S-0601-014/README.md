# SAF-K8S-0601-014 — Image defaults and container runtime enforcement

```sh
python3 lab.py test SAF-K8S-0601-014 --docker-context desktop-linux
```

This case needs Go and a local Docker engine. It builds a static Linux probe
for the amd64 or arm64 kind node. Both images use `FROM scratch` and contain
only the probe and one public marker file. The case checks the image archives
and verifies each image's distinct declared numeric `USER`. No image is pushed.

The same binary observes its actual UID, attempts a write to an existing
image file, and writes and removes a file on an explicitly writable
`emptyDir`. It distinguishes `EROFS` from a discretionary access denial. The
four arms cover a root/writable baseline, a non-root image default with
writable rootfs, a root process with read-only rootfs, and the combined
non-root and read-only Kubernetes settings. The scratch mount works in all
four. The runner deletes the cluster, and the case removes its local build
tags and temporary build files.

These tests exercise image metadata, the final built image and actual process
behavior. An organization's registry and admission gates, exceptions, and
production image and mount inventories need separate verification.

The scratch candidate adds one namespaced native Kubernetes
ValidatingAdmissionPolicy comparison. Five fixed proposals are server-side
dry-run only: four omit or set false one of `runAsNonRoot` or
`readOnlyRootFilesystem`, and one supplies both as true. The same proposals
are admitted before policy activation; after the binding activates, the four
incomplete proposals are denied and the compliant proposal remains
admissible. The policy requires both fields on every regular and init
container. It is bound only to a newly created fixture-labeled namespace. No
Pod from this comparison is persisted or scheduled. The original six image
and runtime assertions remain intact; the candidate has seven total.

For adoption, inventory the exact released image digest and its final USER and
file list in the build pipeline. Verify the deployed admission policy's
effective failure behavior, namespace or workload coverage, and rejection of
missing and false settings before persistence. Include init containers and
all workload controllers in that review. Record the actual explicitly
writable mounts and verify that applications still operate with the root
filesystem read-only. Any exception should be owner-approved, restricted to
non-production debugging, state a reason and expiry, and have a recorded
removal check. These fixture checks do not establish registry coverage,
third-party image inventory, production admission coverage, or exception
governance.

- [OCI image configuration](https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md)
- [Kubernetes v1.36 security contexts](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
