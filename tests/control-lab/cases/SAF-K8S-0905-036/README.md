# SAF-K8S-0905-036 — Trigger a controller-driven workload halt

    python3 tests/control-lab/lab.py test SAF-K8S-0905-036 --docker-context desktop-linux

An in-cluster controller reads an explicit synthetic numeric metric and cutoff. With enforcement disabled, the over-threshold fixture stays active. Once enabled, the workload continues below the cutoff and halts at the cutoff. The controller records intent before scaling and enforcement after the scale update. The original halt record and zero replicas persist through controller restart and when the metric clears. A separate live service still responds.

Production telemetry authenticity, fail-safe recovery and reset procedures, additional workload types and deployment coverage require their own evidence.

- [Kubernetes 1.36 Deployment](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/deployment/)
- [Kubernetes 1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)


The retained reference case verifies one synthetic numeric signal and one
namespace-scoped controller that latches and scales one named Deployment to
zero. It does not establish the authenticity or completeness of deployed
telemetry, production response time, or enforcement for Job, serving, or
pipeline implementations. Complete and retain the following evidence for each
deployed implementation.

1. **Identify authoritative signals.** Inventory each threshold and its
   producer, owner, transport, authentication/integrity protection, freshness,
   schema, units, and workload binding. Show an approved representative signal
   reaches the controller. Define and exercise bounded behavior for missing,
   stale, malformed, duplicate, and unavailable signals; the controller must
   not treat an absent sample as a healthy value. Record only metadata and
   sanitized outcomes where telemetry may contain sensitive data.
2. **Approve the threshold and response.** Retain the policy owner, version,
   threshold, units, comparator (including equality), sample window, and
   expected response deadline. Identify the exact affected workload. Demonstrate
   a below-threshold comparator and the threshold-triggered halt/isolation in
   the actual deployment path. Verify an unaffected workload remains available.
3. **Constrain the actuator.** Inspect effective authorization for the
   controller identity. Permit only the telemetry/policy reads, decision
   record writes, and exact halt operation for the approved target. Verify
   unrelated targets and broader parent-object updates are refused. Confirm
   the action reached the actual Pod/Job/serving endpoint state rather than
   relying on a controller log alone.
4. **Define known halt state and protected evidence.** For each covered failure,
   document the organization-designated known state and the state information
   that must survive failure, consistent with SC-24. Preserve a time-correlated
   signal reference, approved policy revision, trigger decision, actuator/API
   result, target state/endpoints, and any human approval. Restrict evidence
   access, integrity-protect retained records, define retention, and ensure
   telemetry values or credentials are not copied into general logs.
5. **Govern restart and reset.** State whether the halt is latched and what
   signal recovery means. Identify the authorized reset role, required
   revalidation and approval, rollback path, and response if the controller
   restarts or its state store is unavailable. Demonstrate restart while the
   incident condition remains and after it clears; verify no automatic
   reactivation occurs unless explicitly approved by policy. Keep reset and
   approval evidence with the trigger record.
6. **Verify each deployed workload type.** For training Jobs, test the actual
   `activeDeadlineSeconds` limit if used and distinguish that duration limit
   from a safety/resource metric circuit-breaker. For inference serving,
   verify scale-to-zero or traffic isolation at the serving route. For pipeline
   stages, verify the controller halts only the intended stage and prevents
   downstream continuation as designed. If an autoscaler is involved, document
   and test its scale-to-zero prerequisites, including minimum replicas and
   other controller interactions. Do not infer these behaviors from the
   retained Deployment-only reference case.

NIST SP 800-53 SC-24 is conditional: apply the mapping when the adopter assigns
this halt as its known state for an in-scope failure and defines what state
information to preserve. SI-4 monitoring remains a separate function; this
circuit-breaker can only be a downstream response action when the adopter's
SI-4 monitoring detects and routes an in-scope condition. See the versioned
[NIST OSCAL catalog](https://github.com/usnistgov/oscal-content/blob/v1.4.0/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json).

Reference receipts: lab `saf-k8s-control-lab/evidence/SAF-K8S-0905-036/20261123T023730Z-1e1a2e5a/result.json` and framework `saf-k8s-framework/tests/control-lab/evidence/SAF-K8S-0905-036/20261123T023728Z-b405a224/result.json`. Both are six-check passes at catalog revision `cfbdd2886845897e10aef29a646a823328d5ff6e` on separate disposable Kind v1.36.1 clusters, which were deleted. The current publish catalog index is revision `30dc87210fe2f451e90241a8092594763b3a0e4e`; the tested control SHA remains unchanged, but the receipts do not claim execution against that newer full-catalog revision.
