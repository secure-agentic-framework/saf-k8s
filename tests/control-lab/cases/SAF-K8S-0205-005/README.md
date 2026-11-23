# SAF-K8S-0205-005 eBPF program authorization and integrity

The case checks Kubernetes capability admission using only dry-runs. In a restricted Job, a fixture-owned signature gate rejects changed bytes, verifies the approved object, and boots a disconnected Linux guest. The approved harmless program is loaded for inventory and never attached. The guest reports the loaded program and removes the fixture pin.

The signature gate is a userspace fixture. Deployed loader and kernel enforcement, monitor loss and attachment coverage, and approved node and workload boundaries require separate evidence.

```sh
python3 lab.py test SAF-K8S-0205-005 --docker-context desktop-linux
```
