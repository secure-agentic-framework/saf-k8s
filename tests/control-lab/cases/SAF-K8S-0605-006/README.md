# SAF-K8S-0605-006 Pod Security Admission for AI workload namespaces

Run the disposable reference case from the SAF-K8S repository root.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0605-006 --docker-context desktop-linux
```

From the separate Control Lab root, use `python3 lab.py test SAF-K8S-0605-006`
with your Docker context.

The Kubernetes v1.36.1 fixture compares an admitted Restricted-only deviation
with the same request after Restricted enforcement. A compliant comparison
continues to pass. A separate Baseline namespace shows how Restricted warning
and native audit can record a deviation that Baseline admits. The namespace
policy protects pinned PSA labels on creation and update, including removal of
the AI classification label. The case exercises the read-only API views below.

## Verify your implementation

1. Reconcile the authoritative AI workload inventory with the namespaces
   created directly and by operators. Record the owning controller, namespace,
   Kubernetes minor version, expected policy level and any approved exception.
   Review who can set or remove the classification.
2. Select the approved context and namespace name. Read the six PSA labels and
   compare them with the approved levels and version pins. The reference uses
   Restricted for all three modes and v1.36 for each pin. Where an implementation
   permits Baseline, verify the approved minimum and the mechanism that records
   namespaces operating below Restricted.

   ```sh
   kubectl --context "$SAF_CONTEXT" get namespace "$SAF_NAMESPACE" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce} {.metadata.labels.pod-security\.kubernetes\.io/enforce-version} {.metadata.labels.pod-security\.kubernetes\.io/audit} {.metadata.labels.pod-security\.kubernetes\.io/audit-version} {.metadata.labels.pod-security\.kubernetes\.io/warn} {.metadata.labels.pod-security\.kubernetes\.io/warn-version}{"\n"}'
   ```

3. Inspect the effective guard and binding by name. For a native
   ValidatingAdmissionPolicy, use the commands below with the deployed names.
   For an alternate admission engine, inspect the equivalent active policy
   assignment and evaluation status. Verify the scope covers both Namespace
   CREATE and UPDATE, including downgrade and removal of classification.
   Confirm the intended deny and audit actions.

   ```sh
   kubectl --context "$SAF_CONTEXT" get validatingadmissionpolicy "$SAF_POLICY" -o json
   kubectl --context "$SAF_CONTEXT" get validatingadmissionpolicybinding "$SAF_BINDING" -o json
   ```

4. Review PSA admission exemptions by username, RuntimeClass and namespace
   against approved scope, compensating controls, owner and expiry. Match
   existing allowed, denied, and audit records to the evaluated namespace,
   operation, policy, version and time. Keep native PSA audit separate from
   namespace-policy audit. Corroborate central delivery using a corresponding
   received event or an approved evidence export. Use a disposable representative
   environment for any additional behavior comparisons.
5. Retain a scoped verdict, named artifacts and collection time. Label and
   binding evidence establishes configuration. Attribute enforcement to an
   observed admission decision and delivery to a received audit record. Mark
   missing inventory, effective exemptions, admission observations or delivery
   evidence as unverified in the adopter's assessment.

- [Kubernetes v1.36 Pod Security Admission](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes v1.36 auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
