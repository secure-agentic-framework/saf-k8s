# SAF-K8S-0703-014 — HPA replica cap and cloud-cost adoption checks

## Portable Kubernetes demonstration

Run from the SAF-K8S repository root with Python 3.9 or later, Kind 0.32.0 or a compatible release, kubectl compatible with Kubernetes 1.36, Docker, `curl`, and OpenSSL:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0703-014 --docker-context desktop-linux
```

The runner creates one disposable Kubernetes v1.36.1 Kind cluster. The case uses digest-pinned BusyBox and Metrics Server v0.9.1 images. Each bounded CPU worker requests 25m CPU and has a 100m limit; the case creates only local synthetic CPU demand. Metrics Server connects to the case kubelet using a temporary fixture CA and matching node DNS identity.

Expected checks:

1. With HPA `maxReplicas: 4`, measured CPU remains above the 50% target while the Deployment reaches four Ready replicas, above the chosen two-replica threshold.
2. Under the same continuing demand, lowering the maximum to two brings desired, observed, and Ready replicas to two and reports `ScalingLimited=True` with reason `TooManyReplicas`.
3. Both capped replicas remain Ready while the synthetic CPU demand remains measurable.

The test observes the Kubernetes HPA's maximum replica boundary for this Deployment. It does not create cloud resources, GPU workloads, billing events, or actual spend and it does not prove service latency or availability for real user requests.

The fixture creates one control-plane Kind node, one Metrics Server, and at most four CPU workers. Each worker is bounded at 100m CPU and 32Mi memory. The HPA convergence waits are bounded to 210 seconds per phase; cluster startup, manifest download, and uncached image pulls add time. Allow up to about 15 minutes for a first run with uncached images. The expected verdict is phase-based (four replicas under a permissive cap, then two with `TooManyReplicas` while demand stays above target), not tied to a specific wall-clock timestamp.

## Reproducibility evidence

Two distinct runs passed all three checks on separate clusters and reported cleanup as deleted:

- Lab checkout: `evidence/SAF-K8S-0703-014/20261122T054427Z-db22aae5/result.json` (`saf-lab-a20db62b99bd`).
- Framework checkout: `tests/control-lab/evidence/SAF-K8S-0703-014/20261122T054748Z-ce0ee37a/result.json` (`saf-lab-2816bfea0adb`).

Both receipts identify Kubernetes v1.36.1, the same pinned Kind node image, catalog revision `d4328fde2e235c4d4a65baf2e08f7e45cfb81217`, and control fingerprint `2fb7933bcb7686f5829fabc4fe736cb83743ecc3664a2425366eea39610e6eeb`. Evidence from the two checkouts is independent; a mirrored published result is not a second runtime. The open adoption child is `saf-lab-0703-014.1`.

## Deployed provider verification

The HPA test is one component of the control. Verify provider-specific GPU capacity, node-group ceilings, billing alerts, and automated responses in an approved, isolated nonproduction project or account. Do not infer a hard cost limit from a budget notification; inspect the provider's exact configuration and prove what action it enforces.

1. Record the owner-approved test scope, maximum potential charge, region, project/account, test node pool and GPU class, test workload, start/stop time, and cleanup owner before enabling any billable resource.
2. Inventory the real HPA target, minimum/maximum replicas, resource requests, HPA metric and behavior; provider node-pool/autoscaler limits; applicable quotas; billing budget scope and threshold; alert destination; response actor; and permitted automated actions. Bind every identifier to the dedicated test scope.
3. Use the provider's supported budget-event test facility or inject a synthetic event into the exact alert-to-automation path. Verify the below-threshold allowed state and threshold event receipt. If an action is claimed, observe the real provider-side cap or the explicitly approved test-workload pause; an alert or notification alone is not enforcement.
4. Verify scope restrictions by submitting a synthetic event for an unapproved project, pool, or workload. Require the response to refuse the unapproved target and verify the approved workload and unrelated test markers remain unchanged.
5. Exercise a provider-supported missing, delayed, or stale event in the isolated test integration. Verify the documented failure behavior, owner notification, bounded action, and recovery after valid state resumes. Keep any fail-safe action within the approved test project; define production impact and rollback separately.
6. Retain sanitized configuration identifiers, provider audit records, alert-delivery evidence, response principal and scope, before/after replica and node counts, threshold/action result, recovery, and cleanup. Explicitly label controls that report spend without preventing it.

Adopter evidence should connect the organization-approved spend or capacity objective to the deployed HPA, namespace quota, node-group/GPU ceiling, billing signal, and response automation. Also verify least privilege and failure behavior for the response identity. The lab does not define cost thresholds, approve production shutdowns, or cover every cloud provider's billing semantics.

## Mapping scope

The case supports only a conditional, partial contribution to NIST SC-6 when the assessed system's resource-allocation policy uses this workload's HPA maximum as one bounded replica-allocation control. It does not demonstrate allocation to other workloads, priority or namespace quota enforcement, or cloud cost ceilings. CP-2(2), SA-2, SA-8(25), SC-5, and SC-5(2) are not mapped to this case: their capacity-planning, capital-allocation, security-design cost-benefit, denial-of-service, and flooding-capacity obligations are not established by this synthetic HPA comparison.

## References

- [Kubernetes v1.36 Horizontal Pod Autoscaling](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/autoscaling/horizontal-pod-autoscale/)
- [Kubernetes v1.36 Resource Quotas](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/)
- [Metrics Server v0.9.1 release](https://github.com/kubernetes-sigs/metrics-server/releases/tag/v0.9.1)
- [NIST SP 800-53 Rev. 5.2.0 official OSCAL catalog](https://github.com/usnistgov/oscal-content/blob/v1.5.0/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json)
- [NIST SP 800-53B baseline release information](https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final)
