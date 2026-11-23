# SAF-K8S-0205-004 Cilium policy enforcement

The case installs the digest-checked Cilium chart on Kind and probes owned Pods only. It compares behavior with the policy absent and present, and verifies distinct Cilium identities, a denied transport port, a denied HTTP route and a retained approved marker.

The case covers same-node IPv4 Pod traffic with this Cilium version. Deployed paths, rollout and failure behavior, and comparative performance require their own evidence.

```sh
python3 lab.py test SAF-K8S-0205-004 --docker-context desktop-linux
```
