# SAF-K8S-0905-048 Pin OCI model artifact digests

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-048 --docker-context desktop-linux` from the framework checkout.

Kubernetes admission compares the image reference and recorded digest to an immutable review record. The same mutable-tag proposal is accepted before policy activation and denied after it. After the tag points to a replacement model marker, an otherwise well-formed replacement digest with self-declared metadata is denied. The admitted original digest retrieves the exact reviewed manifest and payload from a pinned local registry. The consumer recomputes the manifest, verifies the requested SHA-256, and matches the payload digest and size.

The scope is one governed Pod field and one OCI consumer. Admission uses server dry-run with inert requests. The registry marker is public fixture data. Verify actual producer and repository identity separately from content identity.

## Verify an adopting implementation

1. Inventory the model references used for promotion, Kubernetes rollout, rollback, replication, and loading, including controller-generated inputs and alternate paths. Record the approved registry and repository identity, the exact manifest digest, and a protected reviewer decision.
2. Validate each governed input at the actual boundary against the reviewed digest and repository. Observe denials for a tag-only reference and an unapproved valid digest. Verify the approved reference reaches the actual model consumer.
3. Independently observe receipt of the exact reviewed manifest and blob through the deployed transport. Require the consumer to recompute and compare requested digests and to stop before using mismatched content. Verify loaded identity where the workflow provides it.
4. Follow the actual deployment or promotion record for the reviewed digest. A tag change should leave the approved release pinned to its original bytes. Preserve the comparison, relevant policy revision and decision evidence in the approved store.
5. Verify independent producer identity, approvals, artifact retention, discovery, and availability through the applicable controls. Apply the stated NIST relationships only where the model is within the covered software or component scope.

- [OCI Distribution Specification v1.1.1](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#pulling-manifests)
- [Kubernetes v1.36 validating admission policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST Release 5.2.0 changes](https://csrc.nist.gov/files/projects/Risk-Management/800-53%20Comment%20Site/SP800-53-r5.2.0-changes.pdf)
