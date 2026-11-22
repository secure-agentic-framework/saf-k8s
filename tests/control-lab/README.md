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

For self-contained cases, run `test <control-id>` with
`--await-approval <new-file>` to start the cluster while reviewing the case.
Once reviewed, run `approve <control-id> <new-file>` with the same catalog index.
Use a separate approval file in a private directory outside the case for each
run. The runner checks the approved snapshot before loading the case and cleans
up the cluster on approval timeout or cancellation.

For a static Kind profile, review `kind.yaml` first and add
`--reviewed-kind-config tests/control-lab/cases/<control-id>/kind.yaml` to the
test command. The approved case must contain the same profile bytes. Cases
that generate their Kind configuration use the ordinary test command.
