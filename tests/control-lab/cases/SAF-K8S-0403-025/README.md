# SAF-K8S-0403-025 Secret detection coverage

Run by ID on fresh Kind with local Git and Docker BuildKit available.
A public rule observes an exact fixture marker in Git history, actual OCI
layer contents, a retained ZIP artifact, workload stdout and a lab log
sink. The case verifies source-specific routing to a Kubernetes-backed
fixture alert queue. Each surface also receives a clean example.

The log sink and alert queue are fixture implementations. Assess the
production detector, formats, event delivery and defined detection and
notification windows independently.

- [Git grep](https://git-scm.com/docs/git-grep)
- [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md)
- [Kubernetes logging architecture](https://v1-36.docs.kubernetes.io/docs/concepts/cluster-administration/logging/)

## Verify an adopting implementation

Map each governed publication and runtime surface to an
enabled detector, supported formats, owner, and alert destination. Submit an
approved harmless marker per surface and retain source attribution, detection
latency, delivery receipt, and retention location; submit a clean comparator
to verify no false finding. Document excluded surfaces, exception expiry,
and escalation ownership.
