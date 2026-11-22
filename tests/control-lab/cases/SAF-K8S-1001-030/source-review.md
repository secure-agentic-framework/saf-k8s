# SAF-K8S-1001-030 source review

## Provenance and boundary

- Requested framework revision: `133a8698a45e2b335b51728bf4c62f7bda98d15f`.
- Confirmed the commit exists in `../saf-k8s-framework` and read the pinned
  `markdown/controls/SAF-K8S-1001-030.md` and corresponding `saf_k8s_controls.yaml`
  entry directly from that Git tree.
- Pinned control SHA-256: `eccdf439cf37644aa76c2bd02f45645b12848bec496260572bae76838b4c5e90`
  (matches the local catalog index entry).
- Review date: 2026-11-22.
- The source review and retained runtime evidence use Kubernetes v1.36.1. The
  runner node image is
  `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`.

## 1. Verify the claim

| Catalog obligation | Mechanism and applicability | Evidence needed | Source result |
| --- | --- | --- | --- |
| Collect training Job logs | Kubernetes captures container output and exposes Pod logs; a namespaced collector can request the Job's concrete Pod log subresource. | Compare completed Job stdout with its fixture event; route it with the observed Job Pod name. | Testable for one synthetic completed Job. Does not establish every training framework's output or retained training data. |
| Collect inference service operational logs | A Service addresses selected Pods; it does not itself collect logs. The collector reads the selected fixture Pod's log subresource. | Verify the fixture Pod is running and Service selects it; compare its exact stdout record with receiver state. | Testable for one running Pod behind a case-local ClusterIP Service. Does not establish production service discovery or all replicas. |
| Collect pipeline execution logs | A completed Job Pod supplies one staged pipeline event via its container log stream. | Compare the stage Job's stdout with the fixture event and preserve exact source identity through routing. | Testable for one stage Job. Does not represent a pipeline controller or prove all stages are covered. |
| Route the records to an enterprise logging platform for centralized visibility | The control names an enterprise platform, but the lab can only use a case-owned receiver and route gate. | Deployed destination configuration, permissions, ingest and query evidence, retention and operational evidence from the real platform. | A local receiver only validates fixture routing. It cannot validate the control's enterprise-platform or investigator/operator visibility claim. |
| Apply to all AI/ML workloads and controllers | The control scope is universal across Kubernetes AI/ML workloads and ML pipeline controllers. The control does not specify a collector, discovery mechanism, coverage inventory, or required log taxonomy. | Workload and controller inventory, collector discovery and routing configuration, and independently measured coverage in each intended environment. | Not established by three examples. The control statement's breadth needs explicit supported applicability and coverage criteria. |

## Versioned primary sources checked

- Kubernetes v1.36 [logging architecture](https://v1-36.docs.kubernetes.io/docs/concepts/cluster-administration/logging/): containers commonly write logs to stdout/stderr; Kubernetes captures Pod/container logs and exposes them through the Pod log API. Kubernetes does not supply native log storage for cluster-level logging. The documentation also states `kubectl logs` only returns the latest log file after rotation. These points support the collection mechanism but limit durability and completeness claims.
- Kubernetes v1.36 [RBAC authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/): `log` is a Pod subresource represented as `pods/log`; a namespaced Role can scope a verb to named resources with `resourceNames`. The draft uses `get` only and exact runtime Pod names, with no `pods` list permission. This validates the proposed permission shape, not runtime enforcement; an eventual run must establish the API requests succeed for those names.
- Kubernetes v1.36 [Jobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/): a Job is a run-to-completion controller; completed Jobs normally keep their Pods so their logs can be inspected. This supports the short-lived training and pipeline fixtures, not model-training semantics or long-term log preservation.
- Kubernetes v1.36 [Services](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/service/): Services expose applications running in one or more Pods and the default ClusterIP is reachable only inside the cluster. This supports the internal inference fixture endpoint, not collection by itself.

The primary sources describe Kubernetes mechanics. They do not say that Kubernetes
requires enterprise SIEM/log-platform routing, nor define AI workload classes,
minimum source coverage, log content, or a universal retention/visibility duty.

## 2–4. Proposed runnable evidence

The case creates only case-labelled resources in the runner namespace and uses
ordinary fixture records. Training and pipeline are real `batch/v1` Jobs; inference
is a running log-producing Pod behind a namespace-local Service. All three emit one
synthetic JSON line on stdout. The collector's only API permission is `get` on
`pods/log` for the exact three fixture Pod names. It reads each log through the
Kubernetes API, validates the fixture line, and posts the unchanged event with its
namespace, Pod, container, and workload type to a case-owned router.

The red stage expects three `404 route_missing` responses and an empty receiver.
The route is then explicitly approved in the case-owned router and the same source
records are collected again. The green stage compares exact receiver records with
fixture events and a second, host-side `kubectl logs` read. Stable checks record IDs,
source classes, exact equality, and counts. Raw Kubernetes objects, Job-generated
Pod names, stdout, approval response, and receiver records are separate evidence
files. The case has not been run; none of these are claimed observations yet.

## 5. Disposition

**Source assessment: Partial / unverified as stated.** Kubernetes v1.36 supports the
fixture's stdout collection mechanism and exact Pod log subresource authorization.
That does not establish the control's universal “must collect and route” statement,
all workload/controller coverage, an enterprise destination, or centralized
operator/investigator visibility. The control says “must” without defining an
organization, regulatory, policy, or risk basis for the universal requirement.

The draft can demonstrate only that three harmless fixture sources can be read
through a narrowly scoped Kubernetes identity and that a local route gate changes
receiver observations from missing to exact delivery. Production collector
deployment, real workload discovery, backend permissions, coverage, retention,
availability, and operational search need separate evidence. No claim result was
recorded to the catalog and no Beads issue was inspected or changed.

### Candidate wording for a future catalog review

Where an organization's logging requirements identify AI/ML workload operational
logs as necessary, configure collection and routing for the in-scope training,
inference, and pipeline sources to an approved centralized logging destination.
Maintain an inventory of covered workloads and verify that records remain
searchable with source identity. Set retention and completeness expectations under
separate controls or organization-specific policy.

This is a candidate for follow-up, not an adopted correction. It narrows the
unqualified mandate and makes source inventory, approved destination, and identity
checkable; the applicable organizational basis and relationship to neighboring
coverage, SIEM completeness, and context controls still need review.
