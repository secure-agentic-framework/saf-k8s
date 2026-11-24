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

For `IfNotPresent`, the authorized identity reuses the same cached digest
without a registry read. The comparison without the identity attempts registry
authorization, reports missing credentials, and starts no container while
the digest stays cached on that node.

The case also imports a distinct, digest-pinned BusyBox image through the runtime outside
the kubelet pull path. It checks the exact repository digest through CRI before
comparing a denied cached-only request with an authorized `Always` pull and
startup for the same digest. The registry sees the exact manifest request.
The receipt retains methods and paths, plus response codes when available.

## Verify your implementation

1. Inventory the node pools that can run private images. Record Kubernetes
   and CRI versions, the effective kubelet policy, and the template or image
   that will create replacement nodes. Cover each pool and a representative
   replacement running the exact candidate configuration. Use the provider's
   authoritative configuration evidence where kubelet settings are managed.
2. On a self-managed node, read the loaded configuration using approved
   access to kubelet `configz`. A node proxy grant can confer broad node
   access. Reuse an approved read path or configuration export.

   ```sh
   kubectl --context "$SAF_CONTEXT" get --raw "/api/v1/nodes/$SAF_NODE/proxy/configz" \
     | jq '.kubeletconfig | {
         feature: .featureGates.KubeletEnsureSecretPulledImages,
         policy: .imagePullCredentialsVerificationPolicy
       }'
   ```

   Resolve a missing explicit feature-gate setting using the node's exact
   Kubernetes version and provider configuration. Verify effective
   `AlwaysVerify` or the provider's equivalent behavior. Record separately
   how the node was initially populated. At first enable, or after successful-
   pull records are lost, kubelet classifies existing cache entries as preloaded.
3. In a disposable environment, use a harmless private registry image pinned
   by digest and test identities created for this comparison. Confirm the
   actual target Node and initial image cache state through the runtime.
   Run an authorized pull, retain the registry request outcome, and confirm
   the exact repository digest appeared in the node cache. Keep requests,
   Pods, events, image IDs and registry observations tied to that Node and
   exact digest.
4. Request the same digest using `imagePullPolicy: Never` on that node
   with and without the matching identity. Verify an authorized start,
   a denied counterpart with no started container, and whether either Pod
   contacted the registry. Repeat with `IfNotPresent` or the pull policy
   your workloads actually use. Distinguish local reuse from a new registry
   pull attempt. If images are baked into a node image or loaded outside
   kubelet, include that acquisition path in the adopter comparison.
5. Run the comparison on a newly provisioned replacement as well as a
   current node from each applicable pool. Retain loaded policy, node image
   and version, actual scheduling and run evidence, and provider limitations
   or exceptions. Cached verification may match a prior successful identity
   without contacting the registry. Verify credential rotation and revocation
   independently under SAF-K8S-0601-022 and SAF-K8S-0601-023. Retain the
   authorized and denied outcomes for your credential lifecycle. Keep
   Secret values and credential hashes out of receipts.

[Kubernetes image pull credential verification](https://v1-36.docs.kubernetes.io/docs/concepts/containers/images/#ensure-image-pull-credential-verification) ·
[Kubelet v1.36.1 image pull manager](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/kubelet/images/pullmanager/image_pull_manager.go) ·
[kind local registry](https://kind.sigs.k8s.io/docs/user/local-registry/)
