# SAF-K8S-0104-016 — CIS Benchmark remediation workflow tracking

```sh
python3 lab.py test SAF-K8S-0104-016 --docker-context desktop-linux
```

The workflow fixture tracks an inert configuration finding from detection
through ownership, deadline, remediated revision, independent retest and
closure. A counterfactual assigns the retest to the remediation owner. The
validator rejects that record and accepts the evidence-linked independent
review. The finding, people, dates and historical results are synthetic.

The selected live assessment uses Kind Kubernetes v1.34.8 and Aqua kube-bench
v0.16.0 with CIS 1.12. The scanner mounts only the case-owned kubelet
configuration file read-only and reports check 4.1.9. The fixture observes a
failure on the stock file mode, then tightens the mode and runs a distinct Job
on the same node. The workflow requires the same benchmark, recommendation,
scanner digest, target node and exact file identity. Unrelated successful
results fail closure. The approval, risk priority and workflow identities are
fixture data. The raw receipt records live observations and fixture authority.

Use kubectl v1.34.8 to replay this case from the framework root.

~~~sh
python3 tests/control-lab/lab.py test SAF-K8S-0104-016 --docker-context desktop-linux
~~~

- [Kubernetes v1.34 kubelet configuration reference](https://v1-34.docs.kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/)
- [Kubernetes v1.34 kubelet files](https://v1-34.docs.kubernetes.io/docs/reference/node/kubelet-files/)

- [Aqua v0.16.0 CIS 1.12 node checks](https://github.com/aquasecurity/kube-bench/blob/v0.16.0/cfg/cis-1.12/node.yaml)

## Verify your implementation


1. **Identify it.** Record cluster and affected node/asset IDs, Kubernetes/provider version, CIS Benchmark product and release, profile, recommendation ID, scanner name/version, scan ID, timestamp, scope, and raw failed result.
2. **Prioritize it.** Record the assigned risk rank and the policy basis, including recommendation severity/criticality and affected asset sensitivity or criticality. Link any required triage decision. Apply the organization’s approved due-date/SLA rules and record owner, assignment time and due date.
3. **Track the approved change.** Link the change approval, implementation record and resulting configuration/release revision to that finding. Keep blocked or overdue work visible and escalated under policy.
4. **Rescan the same thing.** Retain a follow-up scan that covers the same cluster/node, benchmark release/profile and recommendation ID. Confirm an explicit passing result for the same applicable check, or documented equivalent evidence when the scanner emits findings only. Preserve scan coverage and raw results. A successful scan job, a different passing recommendation, an omitted target, or an unrelated safe configuration check does not close this finding.
5. **Close with independent review.** An independent reviewer confirms identity, scope, change revision, passing retest, timestamps and evidence links before durable closure.
6. **Keep exceptions distinct.** An exception remains accepted risk, not remediation. Link it to the finding and retain the authorized risk owner, rationale, compensating controls, approval, expiry/re-review date and status. Govern it under [SAF-K8S-0104-017](../SAF-K8S-0104-017/README.md).

## Acceptance evidence

An adopter can demonstrate the control when a reviewer can follow a representative set of applicable findings from versioned scan output, through policy-based priority, owner and deadline, approved change, same-check follow-up scan, and independent evidence-backed closure. Retain an inventory-to-scan coverage record, including omitted/out-of-scope targets and failed or missed runs; report overdue items and approved exceptions separately from remediated findings. The organization should define its sample or population method and cadence, then show that the selected evidence meets it.

The CIS Kubernetes Benchmark version must match the platform and assessment scope. CIS lists Kubernetes Benchmark v2.1.0 for Kubernetes 1.36 and 1.37; verify the exact approved benchmark/profile and recommendation criteria used in your environment. [CIS Kubernetes Benchmarks](https://www.cisecurity.org/benchmark/kubernetes) · [November 2026 version notice](https://www.cisecurity.org/insights/blog/cis-benchmarks-november-2026-update)
