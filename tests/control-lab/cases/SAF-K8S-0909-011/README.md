# SAF-K8S-0909-011

Run `python3 tests/control-lab/lab.py test SAF-K8S-0909-011` from the SAF-K8S repository root. The local case loads fixed retrieved candidates and a separate approval record. It checks the exact source, version and digest, measures relevance using a documented token-overlap score, and forwards the approved top result. A separate in-cluster consumer records actual delivery or its absence.

The fixture covers a small deterministic corpus and one eligibility rule. Verify source and metadata custody, score calibration, alternate paths, and end-to-end prompt assembly and audit in the deployed system.
