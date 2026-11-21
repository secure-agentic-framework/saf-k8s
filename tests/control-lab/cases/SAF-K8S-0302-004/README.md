# SAF-K8S-0302-004 — Host namespace admission

The v1.36.1 case submits hostPID, hostIPC, and hostNetwork separately to the
unenforced API and to namespaces pinned to Baseline and Restricted. Every
request carrying a host namespace field is a server-side dry-run.

In a separate exception namespace, a ValidatingAdmissionPolicy permits one
synthetic hostNetwork request for the approved submitter, service account, Pod
name, and fixture configuration. It requires a read-only root filesystem and
disables automatic token mounting. Requests with a different authenticated
submitter, workload identity, name, configuration, or namespace are denied.
hostPID and hostIPC remain denied. The ordinary isolated Pod reaches Ready.

The case confirms API admission behavior. An actual exception requires separate
approval, expiration, audit, and evidence that its compensating controls work.
NetworkPolicy treatment of hostNetwork Pods depends on the networking
implementation.

- [Kubernetes v1.36 Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes v1.36 NetworkPolicy and hostNetwork](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/#networkpolicy-and-hostnetwork-pods)
