# SAF-K8S-0804-004 Runtime budget and completion example

A real namespace quota admits the standard workload. The same request with declared RuntimeClass overhead exceeds the initial budget. Once an authorized budget change applies, both profiles run to completion and produce the same output. Local submit-to-completion times are recorded as observations of this fixture only.

Both profiles use runc. The example measures neither confidential-computing overhead nor accelerator compatibility. Record actual workload-specific measurements and supported deployment evidence separately.
