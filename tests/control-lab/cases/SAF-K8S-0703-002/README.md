# SAF-K8S-0703-002 — Pod disruption budgets for availability

From the SAF-K8S checkout:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0703-002 --docker-context desktop-linux
```

The fresh Kubernetes v1.36.1 Kind fixture exercises native policy/v1 Evictions on a three-replica Deployment. With no matching budget the API accepts an eviction and the controller replaces the Pod. A matching `minAvailable: 3` budget reports zero allowance and the next eviction receives HTTP 429 while the selected Pod stays Ready. After `minAvailable` changes to 2 and the budget observes the new generation, eviction succeeds and three Ready replicas return. A separate two-replica StatefulSet repeats the zero-allowance refusal with `maxUnavailable: 0`, then verifies acceptance at `maxUnavailable: 1`, a new UID for the targeted ordinal, and two Ready replicas.

## Adopter verification

1. Inventory governed Deployments, StatefulSets, and long-running AI services with owner, namespace, minimum and maximum scale, maintenance path, and availability objective. Record approved exceptions and their compensating measures.
2. Check that each explicit PDB selector covers the intended Pods and review overlapping budgets, autoscaling limits, budget calculations, and the current observed generation and disruption allowance. Retain the actual controller and Pod identities, budget status, and selected policy.
3. In an authorized maintenance rehearsal, verify the effective drain or provider maintenance path uses the Eviction API and handles rejection and retry. Retain the selected workload and Pod, budget decision, recovery time, and service and data health observations against the configured continuity objective. Assess direct deletion, involuntary disruption, and alternate recovery paths separately.
4. For a CP-2(5) mapping, document how the requirement was selected through the applicable baseline, overlay, or approved tailoring, and where the approved contingency plan identifies the essential function, workload, planned maintenance scenario, and continuity objective through restoration. For Article 15(4), document the applicable high-risk AI workload and how planned evictions fit the broader robustness measures.

[Kubernetes v1.36 disruptions](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/disruptions/) · [Kubernetes v1.36 API-initiated eviction](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/api-eviction/) · [NIST SP 800-53B](https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final) · [Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng)
