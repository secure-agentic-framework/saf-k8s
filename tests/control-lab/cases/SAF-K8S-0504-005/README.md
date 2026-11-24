# SAF-K8S-0504-005 Istio proxy tuning

`python3 tests/control-lab/lab.py test SAF-K8S-0504-005 --docker-context desktop-linux`

The disposable cluster installs the pinned Istio configuration used in
SAF-K8S-0504-001. Strict mTLS protects the local fixture Service. The baseline
reads the default proxy resources and records three exact authenticated
requests. Recreating just the backend with explicit proxy CPU and memory
requests and limits changes its rendered proxy configuration. The same
client receives three exact responses after tuning.

A server dry-run refuses a candidate whose proxy request exceeds its limit.
The exact known-good backend still serves authenticated fixture requests.
Peak throughput, latency, GPU behavior, actual ingress hardening, and
approved training exceptions need separate deployment evidence.
