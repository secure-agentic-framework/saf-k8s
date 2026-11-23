# SAF-K8S-0906-006 training data provenance lab

This case builds a live local Kind pipeline from Kubernetes API objects in `case.py`. The runner imports the module and calls `run(lab)`. `SCOPE` describes the case boundary. The runner supplies namespace `saf-test`; this case does not create or own it.

## Flow

The fixture stores each stage in a distinct PVC: ingested source bytes, source receipt, transformed dataset, transformation receipt, and training/release artifacts. It creates a consumer Job for every claim before waiting for PVCs to become `Bound`, supporting storage classes configured with delayed `WaitForFirstConsumer` binding.

1. An ungoverned comparison Job trains on a fixed, benign mismatched synthetic input without lineage receipts. It demonstrates that an ungoverned path accepts missing provenance linkage.
2. A training Job without the approval ConfigMap reports denial. A release Job then runs before training and without approval; it checks that no governed model or release binding exists. An inspection Job independently confirms that state on the artifact PVC.
3. The valid path persists synthetic source bytes and a source receipt, transforms the data and persists a transformation receipt, then runs the deterministic training Job. The training Job checks both approved digests and the source-to-transformation link before writing the model and training receipt.
4. The release Job verifies the model, training receipt, approval, source receipt, and transformation receipt. It writes a release binding only when those lineage checks pass.

The runner reports `red`, `green`, and `positive` outcomes with `lab.check` and writes `lab.evidence/training-data-provenance.json`. Evidence is stable across runs and contains fixed synthetic digests and aggregate observations, not source text or external data.

## Runtime and execution

The real runner must provide the adjacent `SAF-K8S-0908-001/case.py`; `case.py` imports it from `HERE.parent / "SAF-K8S-0908-001" / "case.py"` and calls its `load_runtime(lab)`. That helper supplies the locally loaded Python image used by the Jobs. No temporary filesystem path is embedded in runnable source.

This authoring session did not run the case and did not invoke Docker or Kind. To execute, use the established SAF local Kind runner with this case and its adjacent runtime helper available. The helper is expected to prepare the local image and Kind cluster as part of runner execution.

## Scope limits

All inputs, approval data, transform logic, and model output are invented and deterministic. This lab checks a short provenance chain and a fixture release gate. It is not evidence of production security, durable immutable lineage, a real approval identity/signature, model quality, fairness, rights clearance, a deployed registry control, or coverage of every input to a real model. See the repository-level `review.md` for the source basis and production evidence boundary.
