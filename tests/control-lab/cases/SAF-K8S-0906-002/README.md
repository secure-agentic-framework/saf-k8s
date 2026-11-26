# SAF-K8S-0906-002 — Verify integrity before dataset consumption

Run `python3 tests/control-lab/lab.py test SAF-K8S-0906-002 --docker-context desktop-linux` from the framework checkout.

The five checks use a fixed trusted fixture manifest and immutable test ConfigMap. Kubernetes workloads verify exact segment inventory, sizes, hashes and the pinned Merkle root. Separate Jobs mount the same synthetic dataset read-only. The approved Job independently verifies the manifest and streams four segments totaling 16,384 bytes. The changed-copy Job verifies and refuses the input before its consumption step. The fixture keeps only status and exact synthetic manifest and dataset identifiers in its published receipt.

## Verify an adopted dataset and storage path

1. Identify the authorized dataset version, independently governed signer and verification trust, exact storage version or object identities, expected inventory and partition boundaries. Check manifest signature, freshness, scope and trusted version before reading the data.
2. Verify the trainer or actual consuming service receives the same immutable version that preflight checks. Use benign controlled comparisons with missing or changed segments, an incorrect commitment, and incorrect manifest identity. Observe trusted denial and zero consumer processing on every governed entry point.
3. Define verification cadence, scope, incremental coverage and failed-verification action for the actual dataset size. Record responsibility, approved exceptions and complete inventory coverage.
4. Exercise the authorized storage recovery procedure separately. Restore an approved version, verify the exact inventory and commitment, and observe controlled recovery of consumption. Record service and data recovery objectives, actual results and the owner for outstanding paths.

- [Kubernetes Persistent Volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/)
- [European Commission AI Act Service Desk, Article 15](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-15)

The fixture uses small fixed segments and checks the segmented verification contract. For a deployment, measure throughput and memory at the sizes and concurrency in scope, verify independent manifest authenticity and accepted-partition delivery to the actual trainer, and confirm durable recovery and rejection evidence.


## File-level recovery

The backup Job validates and copies the approved fixture dataset to a separate
PVC. The read-only consumer receives a different replacement PVC containing a
changed segment and records zero consumption. A restore Job mounts the backup
read-only, verifies the expected inventory and commitment, and then restores the
approved bytes. A fresh consumer Job revalidates that replacement copy before
reading the four exact approved segments. All three volumes belong to the same
disposable cluster. For a deployment, exercise the adopted backup provider,
its storage failure domains, and the measured recovery objectives.
