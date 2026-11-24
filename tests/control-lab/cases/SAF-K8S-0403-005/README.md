# SAF-K8S-0403-005 defensive extension

This drop-in `case.py` preserves the published case's client version gate and its existing Secret deployment-diff observations: explicit `--show-secrets=true`, default masking, explicit `--show-secrets=false`, and unchanged resource version. It adds a finite workload comparison on the same disposable Kind cluster.

## Run

Copy this directory over the case directory in the reviewed SAF-K8S checkout, then run from that checkout's root through the normal Lab API entry point:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0403-005
```

The existing runner owns the disposable Kind cluster, `saf-test` namespace, evidence report, and cleanup. This case pins the same Python workload image already used by other published cases. The workload is one Job per mode and an invalid-policy comparison, with `backoffLimit: 0`, a 90-second active deadline, no service-account token, a non-root user, restricted container settings, and a 32 Mi PVC. The workload makes no network requests and reads no Secret. The output policy is controlled by the explicit `OUTPUT_POLICY=disabled|redact` fixture flag.

## What it observes

Each writer Job emits one JSON training-log line and writes separate JSON artifact, checkpoint, and pipeline-metadata records to distinct files on a PVC. These are fixture JSON records, not actual model weights or checkpoint formats. The baseline Job writes the same public synthetic marker to its log and all three persisted outputs. The protected Job applies a structured field policy before serialization: it replaces only `sample`, then retains schema, pipeline, run, event, and output-kind fields. After each writer completes, a read-only reader Job mounts the PVC and prints the three files; the harness reads the actual writer and reader Job logs through `kubectl logs` and compares them in memory.

The test input is fixed in the reviewed case source, generated only inside the Job, and is not supplied by a user or external system; it models an untrusted sensitive field without introducing a real data source. The `OUTPUT_POLICY` control accepts only `disabled` or `redact`, and exits before writing outputs for any other value. Red/green checks fail the case when expected sink data is absent, changed, or still contains the marker.

Sensitive fixture reads use direct captured subprocess calls and deliberately bypass `Lab.command`/`Lab.kubectl`, which write command payloads and outputs to `commands.log`. Neither check receipts nor failure messages include the marker or raw output. Checks retain booleans and sink count only. The public synthetic marker is assembled inside the writer Job from separate string components, not placed literally in a command, manifest, environment value, Secret, or command log.

## Review and limits

This is a custom, local defensive demonstration. Kubernetes documents Jobs as one-off work to completion and recommends a TTL for finished Jobs. The PVC provides a distinct persistent-volume path for the three fixture outputs; Kubernetes documents PVCs as storage requests. The existing diff subcase follows the `kubectl diff` reference, which documents Secret masking as the default and `--show-secrets` as the opt-in to unmasking. Kubernetes Secret guidance separately says applications must avoid logging secret data in clear text. See the primary documentation: [Jobs](https://kubernetes.io/docs/concepts/workloads/controllers/job/), [Persistent Volumes](https://kubernetes.io/docs/concepts/storage/persistent-volumes/), [kubectl diff](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_diff/), and [Good practices for Kubernetes Secrets](https://kubernetes.io/docs/concepts/security/secrets-good-practices/).

The source-backed claims above describe Kubernetes APIs and documented behavior. The assertions about this fixture's log and file contents are proposed observations for the supervisor's live run; this draft has not been executed. It demonstrates a hand-written structured field filter, not a preferred or named real product. It does not establish artifact scanning, checkpoint format coverage, secrets management or injection, a registry's access controls, hosted CI retention, external artifact-store behavior, inference-platform metadata handling, model quality, protection from alternate output channels, or coverage in any production environment. Those scopes require access to the actual hosted CI to inspect retained logs, the selected artifact store to exercise its write/read and retention path with actual formats, the inference platform to inspect persisted metadata and endpoint output paths, and each target environment's deployed configuration and read-back evidence.
