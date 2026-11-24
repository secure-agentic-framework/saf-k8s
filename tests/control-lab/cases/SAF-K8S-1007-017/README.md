# SAF-K8S-1007-017 — Kubernetes release-channel and changelog monitoring for API deprecations

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1007-017 --docker-context desktop-linux
```

The reference test joins a pinned Kubernetes upstream lifecycle record to a
local synthetic AI platform manifest inventory. It uses the Ingress API transition:
the old `networking.k8s.io/v1beta1` API was deprecated before the v1.22 removal, while
`networking.k8s.io/v1` was available from v1.19. The fixtures include a legacy
manifest, a documented stable-API replacement and a synthetic migration review
record. The case reports a pre-upgrade impact alert and then shows that the local
migration evidence satisfies this narrow fixture gate.

The case also reads `/version` and `/apis` from the runner's Kubernetes v1.36.1
cluster. It checks that `networking.k8s.io/v1` is served and the removed
`networking.k8s.io/v1beta1` API group version is absent. These are read-only discovery
requests. The case also creates one isolated CRD and a marker in the disposable
Kind cluster. Requests to its deprecated and current API versions read the same
object. The deprecated version emits the exact configured warning. The current
version returns the object without a warning. The normalized upstream inputs
are pinned in this directory for offline runs.

## Review gates

| Catalog obligation | Case evidence | Result boundary |
| --- | --- | --- |
| Monitor official releases, changelogs and deprecation notices | Versioned lifecycle fixture links the official deprecation warning, tagged v1.22.0 changelog history, v1.22 release announcement and v1.36 migration guide’s v1.22 history; fixture identity and version fields are checked. | Static source-derived fixture; not proof of recurring feed monitoring or alert timeliness in an organization. |
| Identify affected cluster services, AI operators, custom resources, manifests and dependencies | Synthetic inventory links one legacy manifest to a named synthetic AI serving component; the case raises a pre-upgrade alert. | Only one built-in Ingress manifest is represented. No live workload inventory, operator/client code, CRDs, charts or dependency scan. |
| Translate notices into tracked impact alerts before upgrade | The fixture produces an alert for an assessment at v1.21.0 against removal in v1.22.0. | The alert is a local check result, not an external ticket, notification, or proof of lead time. |
| Block an affected upgrade until migration evidence exists | The same alert keeps the synthetic gate closed when migration evidence is absent. | The negative branch is a local decision over synthetic data, not a real upgrade approval system. |
| Begin compatibility review and migration | A synthetic record points to a stable `networking.k8s.io/v1` replacement and reports a narrowly scoped fixture review. | It does not validate controller behavior, production approval, rollout, or workload compatibility. Those evidence fields are explicitly false. |
| Confirm the release target against a live server | Read-only `/version` and `/apis` responses identify the pinned v1.36.1 lab server and its served API versions. | Confirms only this disposable cluster's current discovery surface, not any candidate target or production cluster. |

## Control disposition and evidence requirements

The original catalog statement says:

> Organizations must monitor official Kubernetes release channels, changelog entries, and deprecation notices for API removals that affect cluster services, AI operators, custom resources, manifests, and workload dependencies, and must translate those upstream notices into tracked internal impact alerts before planned cluster upgrades.

The case demonstrates a reproducible parsing, impact-alert and gate pattern for
versioned upstream API lifecycle facts. It does not verify that an organization
subscribes to or reviews release channels, checks changelogs on an established
cadence, assigns owners, tracks SLA/upgrade deadlines, or distributes alerts to
platform, AI/ML, DevOps and security teams. Those are operational obligations and
need separate live evidence, such as dated monitoring records, reviewed change
tickets linked to upstream notices, affected-cluster/component inventories,
owner acknowledgements, migration validation results, and upgrade-gate approval
records. No such organizational evidence is fabricated by this case.

The catalog control's statement is broader than a single executable cluster test.
The read-only demo is appropriate for a defensive monitoring example, but a full
assessment needs those upstream-to-ticket-to-owner records and a separate
deprecated API inventory/migration review across all in-scope AI workloads.
SAF-K8S-1007-018 covers that usage inventory and migration-tracking surface.

The published receipt accompanies this case at
`tests/control-lab/verified/SAF-K8S-1007-017.json` in the framework. It records
the live server version, retained checks and disposable-cluster cleanup.

## Verify your implementation

1. Record each supported Kubernetes minor and the planned upgrade target. Poll
   the official per-minor stable channel on an assigned cadence before the
   upgrade. Save the retrieved marker, timestamp, release/tag identity, tagged
   changelog and relevant deprecation notice. If official sources disagree,
   record the mismatch and corroborate against the published release and the
   same-minor tag comparison before changing the target.
2. Record the effective versions from the target environment and inventory its
   discovery surface.

   ```sh
   kubectl --context "$SAF_CONTEXT" get --raw /version
   kubectl --context "$SAF_CONTEXT" api-resources --cached=false -o wide
   ```

   Tie served APIs to an exact server version and capture time. Discovery lists
   the endpoints the server serves. To measure use, also collect an appropriate
   window of API request evidence and review rendered manifests, jobs, operator
   and client versions, and custom resources. Include CRD served and storage
   versions, status.storedVersions and relevant conversion behavior.
3. Identify active deprecated API calls from received client warnings, audit
   events with `k8s.io/deprecated` or `k8s.io/removed-release`, and the
   `apiserver_requested_deprecated_apis` metric where available. Join the
   deprecated-API gauge with request counters by API group, version, resource,
   and subresource to observe counts over the selected window. Record coverage
   of API server instances and available telemetry. Link relevant callers to
   workload and platform owners. Retain evidence gaps as such.
4. Before the upgrade, track one impact record per affected target and API with
   the upstream source, removal version, mapped artifacts or callers, owner,
   delivery receipt, acknowledgment deadline and remediation evidence. Verify
   the route end to end with an innocuous synthetic impact alert in an approved
   notification test channel. Preserve the intended recipient, sent and
   received timestamps, acknowledgment, escalation action, and related upgrade
   gate decision.
5. Compare the same change with unresolved and mitigated impact in a
   disposable upgrade validation environment. Keep the gate closed for unknown
   release identity, unowned impact, failed delivery, or unverified remediation.
   Check updated manifests and client calls against the actual version and
   validate controller behavior before recording approval. Use SAF-K8S-1007-018
   for the underlying deprecated-API inventory and migration evidence.

## Versioned first-party upstream references

- [Kubernetes warning guidance (published 2020-09-03)](https://kubernetes.io/blog/2020/09/03/warnings/): demonstrates deprecated API warnings and the v1.22 removal horizon for beta API use.
- [Kubernetes v1.22.0 source changelog](https://github.com/kubernetes/kubernetes/blob/v1.22.0/CHANGELOG/CHANGELOG-1.22.md): release-tagged history includes the Ingress v1beta1 deprecation entry.
- [Kubernetes v1.22 release announcement](https://kubernetes.io/blog/2021/08/04/kubernetes-1-22-release-announcement/): confirms removal of deprecated beta APIs including Ingress.
- [Kubernetes v1.36 Deprecated API Migration Guide, Ingress removal in 1.22](https://v1-36.docs.kubernetes.io/docs/reference/using-api/deprecation-guide/#ingress-v122): records the removed Ingress API versions, stable replacement availability and field changes.
- [Kubernetes API deprecation policy](https://kubernetes.io/docs/reference/deprecation-policy/): API removal and warning semantics.
- [Kubernetes audit annotations](https://kubernetes.io/docs/reference/labels-annotations-taints/audit-annotations/): deprecated request and removal release evidence.

### Release corroboration fixture

The captured Kubernetes release listing and the v1.37.2 tagged changelog lag
the published v1.37.2 patch. The fixture corroborates the per-minor download
marker with the upstream stable release record and same-minor commit comparison.
It keeps the linked changelog heading as context. The v1.36 check follows its
own stable marker when the global marker points to v1.37. The isolated
counterfactuals exercise disagreement, an absent comparison, a draft, a
prerelease and a comparison across minor releases. The existing Ingress
checks exercise the removal boundary and live API discovery.

The normalized replay inputs are in `release-evidence.json`. The accompanying
`reference/release-sources.json` records the capture time, official source URLs,
channel results, release identities and recorded digests. The check correlates
those fields with the replay input. Recomputing a historical source digest uses
the bytes from that capture; they are distinct from this normalized case.
Adopters supply polling, alert
delivery and upgrade validation evidence for their target.
