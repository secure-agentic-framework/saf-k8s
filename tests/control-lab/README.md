# SAF-K8S control demonstrations

These local kind tests exercise specific controls in the pinned SAF-K8S catalog.
Each test provisions a disposable Kubernetes cluster and cleans it up afterward.

Use Python 3.9+, kind 0.32.0 or a compatible release, kubectl compatible with
Kubernetes 1.36, and a local Docker engine. Run from the SAF-K8S repository root.

```sh
python3 tests/control-lab/lab.py list
python3 tests/control-lab/lab.py test SAF-K8S-0304-007 --docker-context desktop-linux
```

Use a valid local Docker context for your machine. The first run may pull the
pinned node and workload images. Inspect `cases/<control-id>/` for the runnable
test and fixtures, and `verified/<control-id>.json` for the retained passing
result and its scope. New runs write `evidence/<control-id>/<run-id>/` locally.
