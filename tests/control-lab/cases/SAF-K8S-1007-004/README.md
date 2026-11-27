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

Not demonstrated: complete CIS Kubernetes Benchmark coverage or a kube-bench scan; functional packet filtering (Kind's default networking does not establish NetworkPolicy enforcement); deployed image or scanner coverage; real advisory authenticity, freshness, ingestion, or vulnerability exposure; NVIDIA GPU/CUDA bulletin correlation; managed Kubernetes settings; webhook, OPA, or Kyverno configuration monitoring; ClusterRole/Binding and ServiceAccount-token monitoring; continuous scheduling, production or external alert delivery, remediation approval, or production dashboard behavior. The fixture provides no evidence for those claims in the pinned control.

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


## Native RBAC posture watch

The observer opens an authenticated Role list and watch scoped to the exact
case-owned Role. The unfiltered watch and watch for a different Role both
receive 403. After the stream opens, the test applies a metadata-only change,
widens a rule on the selected Role, and restores the baseline. It also updates
an excluded Role. The observer classifies the three governed events and matches
each to the resource version returned by its API write.

The test uses one finite stream and a projected ServiceAccount token. The
receipt preserves resource identities, rule changes and dispositions. Watch
reconnect, production alert delivery, broader enrolled resources and production coverage
require separate evidence. [Kubernetes API watch](https://v1-36.docs.kubernetes.io/docs/reference/using-api/api-concepts/#efficient-detection-of-changes)

## Native NetworkPolicy posture watch

The additive check opens one authenticated, name-scoped watch for the existing
case-owned `owned-default-deny` policy. Its observer can list/watch only that
named NetworkPolicy; unfiltered and different-name watches must receive 403.

After the first stream closes, the observer holds its last received resource
version while the case records two more API writes. Those writes widen and
restore the same fixture policy. An independent GET sees the restored policy
before the observer resumes. The second stream starts from the saved resource
version and must report both intervening revisions in order, including the
transient drift the GET cannot show. The case records both streams, the exact
API writes and the resume-gate timing. This exercises retained watch history. A separate isolated Kind profile disables only the NetworkPolicy watch cache and uses a bounded compaction interval to produce and observe a real expired-version response, then verifies fresh-list recovery under the same scoped watcher identity. Neither profile exercises policy packet enforcement.
Three independent API writes apply a metadata-only change, a controlled ingress
widening, and exact spec restoration. The receipt retains each write response,
UID, resourceVersion, generation, managed-field timestamps where present, and
watch-event receive timestamps. It compares the ordered events with those exact
write revisions. The test makes no connectivity probes and establishes no CNI
packet enforcement, continuous monitoring service, durable or external alert delivery, or production
coverage.

## Scratch additive: API-side regression alert sink

The scratch copy adds a narrow `events.k8s.io/v1` sink to the existing authenticated
NetworkPolicy watcher. Its namespaced Role retains the selected-policy list/watch
permission and adds only `create` for Events in the owned fixture namespace. The
watcher creates one `Warning` Event for each actual `drift` transition, including a
drift observed after reconnect; metadata-only and recovery transitions emit none.
The runner independently lists the persisted case-labeled Events and requires their
source resourceVersion annotations to equal exactly the two drift write revisions.

Each Event's `regarding` identifies the exact NetworkPolicy UID/name/namespace. Its
`reportingInstance` is the watch Pod UID; the existing Job owner-reference and
ServiceAccount checks bind that Pod to the case observer. A neighbor-namespace create
attempt must receive 403, and the named probe Event must remain absent there. Notes are
fixed safe text and contain no policy rules. This disposable namespace is the only
write scope for the observer's Event permission.

Kubernetes Events have limited retention and are best-effort supplemental data. This
proves an API-side sink in the fixture only; persistent alert transport, SIEM delivery,
monitoring cadence, triage, and approved remediation remain adopter evidence.


## Expired NetworkPolicy watch recovery

A second, separately owned Kind v1.36.1 profile preserves the original profile's default cache and compaction settings. In the isolated recovery profile, the API server disables only the `networkpolicies.networking.k8s.io` watch cache and uses a bounded 15-second etcd compaction interval. One authenticated observer captures a collection resourceVersion, holds it while the case makes two bounded changes to its exact owned policy, and then sends one watch request from that stale version. The proof requires an observed Kubernetes 410 Expired status and an exact-name fresh LIST with the same UID and baseline spec, and a resumed watch under the same Pod and ServiceAccount identity. Two subsequent controlled writes must match the resumed event sequence by UID, resourceVersion, generation, and spec. The API can deliver the status in an ERROR event within an HTTP 200 watch stream. The raw evidence records both the HTTP status and the Kubernetes Status code, together with the API-server arguments.

This is a finite disposable-cluster client lifecycle proof. The short compaction interval is specific to the isolated profile; it does not establish production retention settings, broad watcher coverage, CNI packet enforcement, continuous monitoring, or downstream alert delivery. The API and component documentation describe the watch and compaction behavior.
