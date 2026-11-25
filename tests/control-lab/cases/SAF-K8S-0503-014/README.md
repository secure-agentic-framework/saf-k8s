# SAF-K8S-0503-014 route rate limiting

Use Docker, Kind, kubectl, Python and Helm.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0503-014 --docker-context desktop-linux
```

This test installs pinned Envoy Gateway v1.10.0 in a disposable Kubernetes v1.36.1 Kind cluster. The Gateway uses one proxy replica and a ClusterIP Service. Four requests to an owned marker route succeed before applying the policy. After the active Envoy route configuration shows a three-request-per-minute token bucket, three requests reach the backend and the fourth returns HTTP 429. An unrelated route still returns its marker. The test checks backend arrival counts in both phases.

Traffic stays within the owned test Gateway through dynamically allocated loopback port forwards. The case evaluates a local route quota. Shared budgets across replicas, production route and client coverage, workload capacity, and the separate WAF control need deployed evidence.

[Envoy Gateway v1.10 Helm installation](https://gateway.envoyproxy.io/v1.10/install/install-helm/) and [Envoy Gateway local rate limiting](https://gateway.envoyproxy.io/docs/tasks/traffic/local-rate-limit/).

## Adopter verification

Inventory the selected routes, proxy replicas, effective client identity source and rate-limit keys, burst windows and response behavior. Rehearse with an approved small request sequence from two known identities and correlate gateway decisions with backend arrivals. Check shared or per-replica counters across the actual listeners and verify that independent traffic stays available. Retain the effective policy, route and proxy identities, times, exact counts, and exceptions.
