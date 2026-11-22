# SAF-K8S-0601-024 — Kubelet authorization for cached private images

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0601-024 --docker-context desktop-linux
```

The runner provisions Kubernetes 1.36.1, enables
`KubeletEnsureSecretPulledImages`, and configures kubelet `AlwaysVerify`.
The test places a private fixture registry and only the owned Kubernetes node
on a dedicated bridge. The registry publishes one host-loopback port for its
readiness check. The registry, Skopeo and BusyBox images are pinned by digest.
Keep those images available to the local Docker engine and install Apache
`htpasswd` for the throwaway registry identity.

Before the authorized pull, crictl confirms the exact seeded digest is absent
from the node cache. An authenticated kubelet pull fetches the manifest and
blob and starts the fixture, and the exact digest then appears in the cache.
Two Pods use that same digest and `imagePullPolicy: Never`. The Pod without
the matching Secret identity stays Pending with `ErrImageNeverPull`, while
the authorized Pod starts from the same cache entry. Neither cached-only Pod
reads a registry manifest or blob. The case removes the registry and bridge.

The fixture verifies the strict behavior for one self-managed kubelet. Verify
actual rollout and replacement node coverage, equivalent managed policies,
credential rotation and revocation, externally preloaded images, and
production registries separately.

[Kubernetes image pull credential verification](https://v1-36.docs.kubernetes.io/docs/concepts/containers/images/#ensure-image-pull-credential-verification) ·
[Kubelet v1.36.1 image pull manager](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/kubelet/images/pullmanager/image_pull_manager.go) ·
[kind local registry](https://kind.sigs.k8s.io/docs/user/local-registry/)
