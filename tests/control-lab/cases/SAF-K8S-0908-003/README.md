# SAF-K8S-0908-003

From the control-lab runner directory, run `python3 lab.py test SAF-K8S-0908-003`. Two in-cluster services respond with fixed benign text. The governed service selects ten keyed words from a fixed template. A separate detector workload verifies the keyed words in the returned text. The test compares the unmarked baseline, checks one approved normalization, and rejects an unrelated example. The ephemeral key is mounted only in the governed service and detector. Evidence records decisions and counts.

The ten-position fixture is a demonstration. Evaluate production marking on the applicable model, supported content and transformations, using representative positive and negative data, approved operating thresholds, and quality requirements. Maintain appropriate custody and independent provenance evidence.

[Watermark method research](https://proceedings.mlr.press/v202/kirchenbauer23a.html) · [NIST AI 100-4](https://www.nist.gov/publications/reducing-risks-posed-synthetic-content-overview-technical-approaches-digital-content)
