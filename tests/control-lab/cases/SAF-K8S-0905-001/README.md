# SAF-K8S-0905-001 — Require registry classification in governed namespaces

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-001 --docker-context desktop-linux` from the framework checkout.

Seven grouped checks use native ValidatingAdmissionPolicy, a synthetic registry and zero-replica Deployments. The binding follows a case-selected namespace label and checks every Deployment in scope. The tests compare acceptance before the policy, exact rejections for incomplete or mismatched assignments, refusal when a declared registered system lacks the required marker, and allowed Deployments for the two approved profile assignments. A benign Deployment remains allowed in the separate unselected namespace.

The independent API list and registry readback reconcile all three governed Deployments. Two exact matches are compliant, and the pre-policy incomplete object remains visible as a finding. The benign comparator remains outside the selected namespace.

## Verify an adopted scope and registry

1. Reconcile the AI system inventory against all Kubernetes environments, namespaces, workload APIs and controller paths that can deploy governed systems. Protect the namespace classification and policy binding with appropriate authorization. Compare actual enrollment with the registry, and document coverage and exceptions.
2. Define who owns, approves, updates and reviews classification and registry records. Confirm an independent source of the actual system identity, effective assignment and schema, and retained approval history.
3. Use approved requests to check exact assignment, absent or invalid declarations, wrong registry version, and API updates for each actual governed workload kind and path. Verify the effective classification selects the intended profile. Check authorized exceptions and unselected workloads separately.
4. Review actual profile enforcement with the applicable implementation control, including SAF-K8S-0905-015.

- [Kubernetes ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
