# SAF-K8S-0204-004 Scoped forensic collection

The case uses two disposable workloads and one named fixture collector. It proves authorization for the exact owned file, denies the unrelated workload, records the captured bytes and workload identity, and verifies the original instance continues to run without restarting.

This is a scoped, live filesystem capture over the Kubernetes API. Arbitrary process memory, runtime snapshots, network retention, chain-of-custody storage and provider evidence require separate supported paths and verification.

```sh
python3 lab.py test SAF-K8S-0204-004 --docker-context desktop-linux
```
