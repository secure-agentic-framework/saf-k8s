# SAF-K8S-0905-029 accelerator dependency triage

`python3 tests/control-lab/lab.py test SAF-K8S-0905-029 --docker-context desktop-linux`

This fixture records the UID, resolved image digest and node of a real running
Pod. An offline synthetic component SBOM and independent synthetic native
inventory are tied to that same workload. The unchecked baseline retains the
flagged record. The enabled check refuses missing, stale, incomplete or changed
evidence and retains each separate synthetic cuDNN and fixture driver result.
Correcting either inventory alone leaves the other finding open. Correcting
both closes the synthetic triage record, which links to the original report in
the Kubernetes API. Raw evidence includes the observed runtime and report IDs.

Actual accelerator packages, advisory feeds, continuous remediation, deployment
ownership and hardware coverage require separate validation.
