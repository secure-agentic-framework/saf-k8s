# SAF-K8S-1007-004 — Synthetic posture and drift assessment

Run through the existing control lab runner from the SAF-K8S framework checkout:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1007-004 --docker-context desktop-linux
```

The runner creates a fresh Kind v1.36.1 cluster with its node image pinned by digest. This case creates a separate owned namespace with a mock Python Deployment, a restricted Pod Security Admission profile, a default-deny NetworkPolicy, and a namespaced Role limited to `get` on one named fixture ConfigMap. The mock container image is digest-pinned and has no network client workload; it only sleeps.

The case captures API-visible baseline state, widens the owned namespace's Pod Security enforcement label, adds allow-all ingress to the owned NetworkPolicy, and adds a `list` verb to the owned Role. It checks that all three changes are detected, reapplies the fixture's desired resources, and compares live API state to the desired profile. It then changes a policy in an explicitly out-of-scope fixture neighbor namespace and verifies that the owned-resource fingerprint remains stable.

`fixtures.json` contains offline, fictional advisory records and a synthetic component inventory. The case demonstrates a local exact-match join and a version near miss only. It does not represent an actual CVE, vulnerability finding, scanner result, feed, source, or affected product.

Raw API snapshots and assessment inputs are written to the run evidence directory. The case creates no Secret resources and its raw artifacts contain only synthetic metadata and scoped Kubernetes objects. The supervising runner records its command log and per-assertion result. This is one scenario with red-phase drift detection and green-phase baseline/recovery checks; the runner records exact live observations.

## Coverage and limits

Demonstrated in this fixture: API-visible posture snapshots; drift detection for one Namespace's Pod Security Admission labels, one NetworkPolicy, and one namespaced Role; desired-state recovery by reapplying owned manifests; digest-pinned mock workload identity; exact synthetic advisory/component matching and a near miss; and exclusion of an out-of-scope fixture neighboring object from the fixture's fingerprint.

Not demonstrated: complete CIS Kubernetes Benchmark coverage or a kube-bench scan; functional packet filtering (Kind's default networking does not establish NetworkPolicy enforcement); deployed image or scanner coverage; real advisory authenticity, freshness, ingestion, or vulnerability exposure; NVIDIA GPU/CUDA bulletin correlation; managed Kubernetes settings; webhook, OPA, or Kyverno configuration monitoring; ClusterRole/Binding and ServiceAccount-token monitoring; continuous scheduling, near-real-time alert delivery, remediation approval, or production dashboard behavior. The fixture provides no evidence for those claims in the pinned control.

The control's statement about systematic lifecycle monitoring is testable only for this finite synthetic resource scope. A successful case would support the narrow implementation behavior above, not prove organization-wide continuous security posture management.

## Primary references

- [Kubernetes v1.36 Pod Security Admission](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-admission/) describes namespace labels and the enforce, audit, and warn modes.
- [Kubernetes v1.36 Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/) defines the privileged, baseline, and restricted profiles.
- [Kubernetes v1.36 NetworkPolicies](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) describes API policy semantics and notes that enforcement depends on a supporting network plugin.
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/) documents namespace-scoped roles and rule semantics.
- [Kind Quick Start](https://kind.sigs.k8s.io/docs/user/quick-start/) describes selecting a Kubernetes node image with `--image`.
- [Docker Official Images Python metadata](https://github.com/docker-library/official-images/blob/master/library/python) lists the official Python image tags and architecture metadata. The fixture pins the exact image manifest digest.

## Deployed adopter evidence

1. Inventory customer-configurable and provider-managed security settings; record owner, exact baseline/version, resource scope and how each setting is exposed to monitoring.
2. For each in-scope AI namespace, capture the effective PSA labels, NetworkPolicy objects and rules, RBAC Roles/Bindings, and the assessment's precise coverage boundary. Where NetworkPolicy enforcement is relied on, verify the deployed CNI provider/version and an approved safe connectivity test; an API object alone does not prove packet filtering.
3. Attach a current benchmark/CIS scan and its tool/version, exceptions, and coverage if the catalog's CIS statement is claimed. Attach independent image/scanner results and advisory source/authenticity/freshness evidence for vulnerability exposure claims.
4. Demonstrate continuous collection cadence and alert delivery from the production monitoring service; record actor, timestamps, reviewed drift, remediation approval, outcome, and escalation. The case only runs a local observation once.
5. Link posture findings to the AI risk register only where the organization has identified the relevant AI risk. Document periodic review roles/frequency and any error or affected-community impact reporting separately.
6. Review the broad Article 15.5 claim against model/data poisoning, adversarial examples, confidentiality and model flaws; this case establishes only selected Kubernetes configuration controls.

The scratch mapping plan corrects the MEASURE 1.2 row and selected same-source misattributions. It does not purport to disposition every current crosswalk row for this control.

## Exact scanner-to-Pod evidence

The case builds a harmless Python package fixture using the pinned companion
builder. Pinned OSV-Scanner reads the same image offline using a fictional
advisory. This offline PyPI fixture disables DPKG extraction. The proof binds
image configuration, scanner history and every nonempty layer digest to the
preserved OCI manifest and compares that exact digest with the observed Kind
Pod image ID. The posture result identifies the fictional finding, with missing
or mismatched observations classified unknown. Raw evidence preserves the
scanner output, report digest, OCI subject, and exact runtime identity.

- [OSV-Scanner v2.7.1](https://github.com/google/osv-scanner/releases/tag/v2.7.1)
