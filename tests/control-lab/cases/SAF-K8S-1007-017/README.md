# SAF-K8S-1007-017 — Kubernetes release-channel and changelog monitoring for API deprecations

```sh
python3 lab.py test SAF-K8S-1007-017
```

This read-only example joins a pinned Kubernetes upstream lifecycle record to a
local synthetic AI platform manifest inventory. It uses the Ingress API transition:
the old `networking.k8s.io/v1beta1` API was deprecated before the v1.22 removal, while
`networking.k8s.io/v1` was available from v1.19. The fixtures include a legacy
manifest, a documented stable-API replacement and a synthetic migration review
record. The case reports a pre-upgrade impact alert and then shows that the local
migration evidence satisfies this narrow fixture gate.

The case also reads `/version` and `/apis` from the runner's Kubernetes v1.36.1
cluster. It checks that `networking.k8s.io/v1` is served and the removed
`networking.k8s.io/v1beta1` API group version is absent. These are read-only discovery
requests. The case never applies a manifest, creates or changes an object, reads
an external endpoint, or polls a release feed at runtime. The pinned source data
is retained in this directory so that the assessment is reproducible offline.

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

This authoring pass did not execute the case. A supervisor run should retain the
normal lab result and transcript, verify the exact runner server version and
discovery payload, confirm that all checks are based on checked-in fixtures and
read-only GET requests, and record cleanup status. The expected check evidence is:
pinned fixture integrity; server `gitVersion`; discovered stable and removed
group/version values; the alert's inventory ID, API version and target release;
the closed-gate observation without migration evidence; and the migration fixture's
replacement version and deliberately false runtime validation/production approval
flags. No lab observation or organization-level
monitoring record exists yet.

## Provenance

| Field | Evidence |
| --- | --- |
| Catalog commit and original control | Catalog revision `133a8698a45e2b335b51728bf4c62f7bda98d15f`; original control SHA-256 `86bede5c4a8f71a86b0b7f0e14ac9d318020fac42d6bf4cbbc9b625681470614`; source `../saf-k8s-framework/saf_k8s_controls.yaml`, control `SAF-K8S-1007-017`. |
| Current framework markdown reviewed | `../saf-k8s-framework/markdown/controls/SAF-K8S-1007-017.md`; statement, objective, rationale, scope and enforcement reviewed against the original catalog entry. |
| Primary bead | Not inspected or changed in this authoring-only pass. |
| Reviewer and date | Authoring review, 2026-11-21; execution review remains outstanding. |
| Tested platform | Kubernetes v1.36.1, verified with read-only version and discovery requests. See `verified/SAF-K8S-1007-017.json`. |
| External/runtime boundary | Upstream links are documentation-only. No release-feed fetch, external runtime request, vulnerable API object or cluster mutation is performed. |

## Versioned first-party upstream references

- [Kubernetes warning guidance (published 2020-09-03)](https://kubernetes.io/blog/2020/09/03/warnings/): demonstrates deprecated API warnings and the v1.22 removal horizon for beta API use.
- [Kubernetes v1.22.0 source changelog](https://github.com/kubernetes/kubernetes/blob/v1.22.0/CHANGELOG/CHANGELOG-1.22.md): release-tagged history includes the Ingress v1beta1 deprecation entry.
- [Kubernetes v1.22 release announcement](https://kubernetes.io/blog/2021/08/04/kubernetes-1-22-release-announcement/): confirms removal of deprecated beta APIs including Ingress.
- [Kubernetes v1.36 Deprecated API Migration Guide, Ingress removal in 1.22](https://v1-36.docs.kubernetes.io/docs/reference/using-api/deprecation-guide/#ingress-v122): records the removed Ingress API versions, stable replacement availability and field changes.
- [Kubernetes API deprecation policy](https://kubernetes.io/docs/reference/using-api/deprecation-policy/): explains Kubernetes API deprecation/removal guarantees and warning mechanisms.

### Release corroboration fixture

The captured Kubernetes release listing and the v1.37.2 tagged changelog lag
the published v1.37.2 patch. The fixture corroborates the per-minor download
marker with the upstream stable release record and same-minor commit comparison.
It keeps the linked changelog heading as context. The v1.36 check follows its
own stable marker when the global marker points to v1.37. The isolated
counterfactuals exercise disagreement, an absent comparison, a draft, a
prerelease and a comparison across minor releases. The existing Ingress
checks exercise the removal boundary and live API discovery.

The normalized capture and its source URLs are in `release-evidence.json`.
The case uses the captured snapshots offline. Production polling, alert
delivery and validation on an actual upgrade remain separate requirements.
