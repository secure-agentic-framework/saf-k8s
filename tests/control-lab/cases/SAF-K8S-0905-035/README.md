# SAF-K8S-0905-035 — Roll back a degraded model canary

    python3 tests/control-lab/lab.py test SAF-K8S-0905-035 --docker-context desktop-linux

A restricted rollout-analysis Job samples the actual candidate endpoint and evaluates an error-rate and latency threshold. In the enabled cases, one Kubernetes API update records the decision and redirects the Service to stable. A separate observer verifies that the route serves the stable response. The disabled and healthy cases leave the candidate selected.

Production rollout time, thresholds, network behavior, model health, retention and multi-replica behavior require deployed evidence.

- [Kubernetes 1.36 Services](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/service/)
- [Argo Rollouts analysis semantics](https://argoproj.github.io/argo-rollouts/features/analysis/)

## Verify an adopting rollout

1. Inventory each deployed rollout controller and version, rollout mode, stable/candidate identity, and the exact route or traffic object that the controller changes.
2. Preserve the deployed analysis/metric configuration: signal source, sample window, threshold, failure and unavailable-data behavior, and the policy that enables automatic rollback.
3. For each applicable mode, use an approved nonproduction rehearsal or retain a naturally occurring controlled canary event. Show healthy candidate behavior and the error or latency condition, the controller's automatic rollback decision, reason, and timestamps.
4. Independently read the resulting rollout state and route/data-plane response; confirm traffic returns to the known stable revision and record replica/endpoint state and any in-flight or completed requests affected.
5. Retain controller events/logs and the operational incident record, including rollback completion, alerts/notification, evidence retention, and any separate transaction reconciliation. State which modes were not assessed.

The SI-4 relationship applies only to the selected rollout-health indicators when adopted in the system-monitoring program. [NIST SP 800-53 Rev. 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf#page=364)
