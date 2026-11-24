# SAF-K8S-0104-015 retaining benchmark evidence

Run `python3 tests/control-lab/lab.py test SAF-K8S-0104-015 --docker-context desktop-linux`
from the framework root or invoke `lab.py` in the lab checkout.

Two explicitly synthetic reports exercise evidence retention and trends
on a disposable Kubernetes v1.36.1 cluster. A mutable latest-only
ConfigMap loses the prior report. A case-owned PVC retains both byte
streams and their manifest after the collector Job and Pods are deleted.
Two successive reader Jobs check the stored digests and contents. The
comparison uses bytes read back from the retained archive to report one
regression and one sustained passing check over the two fixture dates.

The case uses a local node-backed PV. Its archive lasts for the
disposable test. Deployed evidence access, retention windows, durability,
and posture reporting over actual assessments remain separate.

- [Kubernetes persistent volumes and Retain policy](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/)
- [CIS Kubernetes Benchmarks](https://www.cisecurity.org/benchmark/kubernetes)
- [Aqua kube-bench](https://github.com/aquasecurity/kube-bench/tree/v0.16.0)

The independent reader Jobs use read-only mounts. Each successfully reads the
retained records and observes the expected read-only failure for a write
attempt. The trend check also rejects a different scope and a changed or
duplicate check population before publishing its comparable result.

## Verify your implementation

1. Inventory applicable clusters, providers, versions, scanner configurations,
   profiles and assessed node or component populations. Compare the approved
   scan cadence with actual start, finish and report times. Keep failed,
   incomplete and missed assessments visible.
2. Select the authoritative archive. Verify effective write, read and delete
   permissions, the configured retention window and expiry, and who can change
   them. Demonstrate historical retrieval using the normal reviewer role.
   Verify report integrity against protected provenance or a separately
   protected manifest. Retain evidence of backup and restoration at the
   failure scope required by your policy. A Kubernetes reclaim policy covers
   volume reclamation after a claim is released.
3. Build trend series only from comparable results. Record stable cluster and
   assessment IDs, scope, date, benchmark release and profile, scanner
   configuration, and both the eligible and assessed check populations.
   Report denominator changes, omitted targets, scan failures, additions
   and removals explicitly. Start a new series when the benchmark,
   population or assessment method changes unless a reviewed mapping
   establishes comparability.
4. Retain the original reports, protected digests, retrieval and restore
   observations, comparison inputs and coverage, and the decisions taken
   in response to changes. Where Article 9(2) applies, link the specific
   infrastructure risk and trend to the in-scope AI system's lifecycle
   review and record the resulting decision.

- [Official text of Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng/pdf)
