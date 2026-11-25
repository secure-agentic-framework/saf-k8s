# SAF-K8S-0702-019 — Supplementary namespace isolation controls

The case exercises Kubernetes v1.36.1 API authorization, kindnet NetworkPolicy,
and namespace-targeted admission across distinct synthetic AI and general
namespaces.

- An AI-namespace RoleBinding grants one synthetic ServiceAccount a named
  ConfigMap GET. The same read was forbidden before binding. Another record
  in the AI namespace and the matching record in the general namespace remain
  forbidden. The API requests use the runner's synthetic impersonation.
- Four owned Pods provide clients and inert HTTP listeners on TCP/8080. Once
  the policy converges, both cross-namespace probes fail. The allowed AI path
  and the general namespace's own path still return the fixed markers.
- A ValidatingAdmissionPolicy binding selects the labeled AI namespace. Missing
  and invalid workload classifications pass the initial server dry-run and
  are rejected after policy activation. The approved AI classification and
  an unclassified workload in the general namespace are still admitted.

Production evidence needs recurring isolation checks, coverage of the actual
tenant workloads and network plugin, authentication and RBAC governance,
and controls for the disallowed cross-namespace references used by the
deployment. The example tests namespace-targeted classification admission.

From the repository root, run the case by ID.

```sh
python3 lab.py test SAF-K8S-0702-019 --docker-context desktop-linux
```

In the framework repository use `python3 tests/control-lab/lab.py` with the same
arguments. The runner prints the receipt and cluster cleanup outcome.

- [Pinned SAF-K8S control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0702-019.md)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes v1.36 Network Policies](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Kubernetes v1.36 Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)

## Adopter verification

1. Inventory tenant namespace labels, effective identities and RBAC, and the
   exact network plugin and version that enforces the policy. Include actual
   Pod selectors, routing profiles and applicable provider limitations.
2. In an approved rehearsal, confirm denied cross-tenant authorization and
   connectivity and preserved permitted use for the selected flows. Retain
   the actual caller, target, authorization and transport results.
3. Inventory application and extension API fields that can reference objects
   in another namespace. Test authorized and denied reference tuples with
   the actual API and admission policy. Record exceptions and responsible
   approvers.
4. Retain periodic inventory and drift decisions with an accountable owner.
   When Article 4a applies, tie the evidence to the relevant protected
   workloads and effective mechanisms that limit the re-use of covered data.

[Article 4a official text](https://eur-lex.europa.eu/eli/reg/2026/1744/oj/eng).
