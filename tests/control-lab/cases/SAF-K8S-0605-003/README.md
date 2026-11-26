# Verify signed Kubewarden policy admission

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0605-003 --docker-context desktop-linux
```

The pinned Kubewarden controller and PolicyServer enforce a signed policy for one owned ModelDeployment scope. Independent build and sandbox checks cover the authored policy. Monitor mode records a would-deny result while the API admits the request. Protect mode verifies allowed and refused creates and updates, and a case outside the enrolled namespace remains admitted. An authored promotion case also checks policy digest, signer and safe refusal of excluded policy artifacts.

For adoption, record the installed controller and PolicyServer versions, signed WASM digest, policy source and approved build lockfile. Verify the actual approved signer and independently test an otherwise valid artifact signed by an unauthorized identity. Inventory protected resources and namespaces, exceptions and the exact live selectors. Compare approved requests, Monitor findings, Protect denials and any allowed excluded cases. Verify the ready policy generation, drained older Monitor Pods and fresh Protect behavior before treating the rollout as complete. Keep policy decision, object binding, signer and rollout evidence with the authorized source revision.

[Kubewarden v1.36 Monitor mode](https://docs.kubewarden.io/admission-controller/1.36/en/reference/monitor-mode.html) · [Kubewarden secured policy supply chain](https://docs.kubewarden.io/admission-controller/1.36/en/howtos/security-hardening/secure-supply-chain.html)
