# SAF-K8S-0905-006 — Verify model retirement and dependent notice propagation

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-006 --docker-context desktop-linux` from the framework checkout.

The eight checks use inert model records, a fixed lineage graph and one case-owned storage fixture. They compare immediate-only and complete lineage traversal, track affected correction and deletion notices, preserve the unrelated comparator, verify digests of archived fixture data and observe PVC protection while an active Pod references the claim. After the reference ends, the native API objects are removed and the fixture archive and propagation records remain readable.

## Verify an adopted model lifecycle

1. Inventory exact version identities and authoritative model stores, deployment references, archives, backups, caches, replicas and retained copies. Record who can authorize deprecation, archival, release removal and disposition. Verify archive integrity and approved restoration where applicable.
2. Reconcile ML-BOM and actual provenance identifiers to every affected parent, release and downstream artifact in the applicable environment. Trace an authorized correction or deletion notice through every affected dependency and assign the required follow-up. Verify the actual action and distinguish unresolved records.
3. Follow a governed retired version through withdrawal and approved disposition. Verify the supported provider, storage and key procedures for the actual copies in scope, applicable retention, backups and recovery, and independent authorization and outcome evidence.
4. Record how privacy and data-governance owners decide applicable obligations and exceptions for each case. Retain sanitized identifiers, version history, decision provenance and verified outcomes.

- [Kubernetes Persistent Volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/)
- [GDPR, Articles 16 and 17](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng/)
- [EDPB Opinion 28/2024 on AI models](https://www.edpb.europa.eu/system/files/documents/2024-12/edpb_opinion_202428_ai-models_en.pdf)
