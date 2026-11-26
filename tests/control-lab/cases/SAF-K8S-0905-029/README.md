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

## Verify a deployed accelerator inventory

1. Identify actual accelerator workloads and resolved image digests. Join installed CUDA and other libraries from the software inventory with separate host driver, device-plugin and toolkit evidence for the actual assigned node and accelerator type.
2. Verify approved tools, scope, evidence sources, report freshness, and a recurring scan and intake trigger for each covered component. Confirm unmatched or incomplete identity and component coverage create review-needed findings.
3. Trace a controlled recorded finding through source intake, version matching, risk review, ownership and due date. Record the decision, corrective or compensating action and approval. Reinspect the exact deployed node, workload and image after remediation and verify closure or expiry of the exception.
4. Identify unmonitored accelerator classes, workload paths, host versions and upstream feeds. Retain coverage and timing evidence alongside the specific records and escalation responsibility.
