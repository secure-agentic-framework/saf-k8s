# SAF-K8S-0501-004 — Cilium HTTP method enforcement

```sh
python3 lab.py test SAF-K8S-0501-004 --docker-context desktop-linux
```

The fixture starts a pinned kind cluster, verifies the SHA-256 of the
published Cilium 1.20.5 Helm archive, and installs it only in the
runner-owned context. Cilium takes ownership of CNI configuration before
the case creates its two HTTP Pods. Helm must be available locally.

Before policy, both GET and POST to the same test listener and path return
the exact harmless marker. The applied CiliumNetworkPolicy allows GET.
The same listener still answers with its marker on GET, while Cilium denies
POST with HTTP 403. This is Cilium HTTP policy evidence on the local node.

FQDN enforcement, global policy precedence, Calico-specific behavior and
provider integration require their own evidence.

[Cilium policy language](https://docs.cilium.io/en/v1.20/security/policy/language/) ·
[Cilium v1.20.5 release](https://github.com/cilium/cilium/releases/tag/v1.20.5) ·
[Cilium CNI configuration](https://docs.cilium.io/en/v1.20/network/kubernetes/configuration/)
