# SAF-K8S-0204-003 — Filesystem drift comparison and alert receipt

```sh
python3 lab.py test SAF-K8S-0204-003 --docker-context desktop-linux
```

Two Jobs start from the same digest-checked image. The lab binds the
observed container image to the built fixture artifact by matching
ordered filesystem layer digests, platform and build label to the node's
CRI metadata. The build index and imported runtime identities are recorded separately. An owned image file is rewritten with the same bytes
and then with different content. The read-only root refuses the operation,
while the approved writable volume changes in both Jobs. An independent
comparator classifies only the changed image-backed content as drift and
sends the attributed alert to a separate Pod. The receipt matches the
actual source Pod, runtime image, path, and before and after digests.

## Verify deployment applicability and evidence

1. Identify the approved image digest and applicable workload, node,
   filesystem and mount paths. Document the exact writable, temporary
   and persistent exceptions, their owners and expiry conditions.
2. Verify that the implemented comparator uses a trusted independent
   baseline and can attribute changes to the correct workload and image.
   Use disposable owned paths to check same-content writes, actual content
   changes and allowed state. Record unknown baselines and unsupported
   paths as evidence gaps.
3. Verify the actual alert pipeline and receiver. Reconcile content/path
   evidence, workload identity, destination, delivery and analyst handling.
   Check false positives from expected mounts, image changes and approved
   state, and test drop, retry and redelivery under the applicable schedule.
4. Verify read-only root and required write functions separately. For
   node- or runtime-level monitoring, check sensor deployment, paths,
   data sources, and privileges. Process and loader events use their own
   instrumentation and evidence.

[Kubernetes v1.36 container security context](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/security-context/) ·
[Kubernetes v1.36 image identity](https://v1-36.docs.kubernetes.io/docs/concepts/containers/images/)
