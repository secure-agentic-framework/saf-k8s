# SAF-K8S-0504-001 workload identity and current authorization

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0504-001 --docker-context desktop-linux
```

The case installs pinned Istio in a fresh Kind cluster. The destination proxy
records the certificate URI of each source identity. Both identities can reach
both routes before policy activation. After activation, two fresh client
proxies use the same ServiceAccounts. The approved identity still reaches the
allowed route, and the other three combinations receive HTTP 403.

The evidence covers fresh client proxies and the two test routes. Beads tracks
established connections and production deployment coverage separately.

[Istio authorization](https://istio.io/latest/docs/reference/config/security/authorization-policy/)
· [Istio peer authentication](https://istio.io/latest/docs/reference/config/security/peer_authentication/)
