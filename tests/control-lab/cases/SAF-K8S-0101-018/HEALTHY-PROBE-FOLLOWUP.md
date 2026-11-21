# SAF-K8S-0101-018 — Authenticated kubeadm probes

The revised catalog record selects this case by control ID. It uses the pinned
Kubernetes v1.36.1 kind cluster and verifies these states.

- The default API server answers the unauthenticated health request.
- Disabling anonymous authentication while leaving the default probe
  configuration makes the static Pod unready. Kubelet records HTTP 401.
- Authenticated startup, readiness, and liveness probes restore Ready while
  unauthenticated health continues to return 401.
- The control plane stays Ready across two full probe intervals with the same
  container and restart count. An authenticated namespace read still succeeds.

A temporary client certificate has explicit GET permission for the two health
paths. The case verifies that this identity receives Forbidden for namespace data.
The API-server fixture mounts the node's kubectl binary and the scoped kubeconfig
read-only. Client credentials stay out of evidence and are cleaned up with the
fixture. Deployment-specific bootstrap checks and managed-provider coverage are
tracked separately.

- [Kubernetes v1.36 anonymous authentication](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests)
- [Kubeadm API server probe configuration at v1.36.1](https://github.com/kubernetes/kubernetes/blob/v1.36.1/cmd/kubeadm/app/phases/controlplane/manifests.go)
