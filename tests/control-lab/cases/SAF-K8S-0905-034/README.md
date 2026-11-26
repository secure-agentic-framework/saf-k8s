# SAF-K8S-0905-034 — Canary version isolation and route integrity

Run from the framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0905-034 --docker-context desktop-linux
```

From the lab checkout, invoke `python3 lab.py` with the same arguments.
The fixture routes a fixed cohort to two inert Services in separate
namespaces. The candidate identity cannot change the approved route.
The same direct candidate-to-stable traffic succeeds before NetworkPolicy
and is denied afterward. The approved 80/20 routing remains effective.
After withdrawing the candidate, the stable route still serves the cohort.

## Verify the adopted rollout

1. Identify the actual routing controller and approved cohorts, stable
   and candidate workloads, immutable release identities, route owners,
   candidate authority, and applicable hardware or runtime separation.
2. Exercise allowed policy change by the authorized role and a refused
   change by the candidate identity. Independently read the live route
   configuration, affected backends and decision records.
3. Compare approved cohort behavior and a direct forbidden candidate
   path from the actual adopted network. Observe the selected routing
   layer, policy implementation and separate version health.
4. Withdraw the candidate through the approved staging workflow and
   confirm stable continuity and the expected route transition.
   Verify automated rollback and health-trigger policy under the
   separate recovery control where applicable.
5. Verify actual resource and accelerator isolation if required by the
   release design. Keep observed traffic, identity, version and
   availability evidence with the approved rollout record.

[Kubernetes NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/),
[Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/),
and [Gateway API traffic splitting](https://gateway-api.sigs.k8s.io/guides/user-guides/traffic-splitting/).
