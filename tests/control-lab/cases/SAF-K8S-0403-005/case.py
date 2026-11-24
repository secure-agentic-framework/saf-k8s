"""Extend the existing kubectl Secret diff check with synthetic pipeline sinks."""
import base64
import json
import subprocess
from time import monotonic, sleep


SCOPE = (
    "Disposable Kind v1.36.1 fixture. Preserves the published kubectl Secret diff "
    "observations, then runs one bounded Kubernetes Job twice with public synthetic "
    "input: once with output filtering disabled and once with a structured field "
    "redaction policy. It treats the sample as untrusted output data and validates "
    "the fixture flag against a closed set. The Job writes separate artifact, checkpoint, and pipeline "
    "metadata JSON records to a PVC and prints a training-log JSON record. Output "
    "values are inspected only in memory and are never written to lab evidence or "
    "command logs. An independent read-only Pod observes records after the Jobs complete. "
    "An invalid policy Job stops before creating sinks. Deployed products and binary artifact formats need separate evidence."
)
FIELD_MANAGER = "saf-lab-diff"
DIFF_NAME = "synthetic-diff-record"
DIFF_BEFORE = "public-fixture-record-A"
DIFF_AFTER = "public-fixture-record-B"
PVC = "saf-0403-output"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SINKS = ("artifact", "checkpoint", "pipeline-metadata")
REDACTED = "[REDACTED]"

# The complete marker is assembled in the workload, rather than embedded in a
# manifest/command that the harness's normal command logger would retain.
WORKLOAD = r'''import json, os, pathlib
marker = "-".join(("PUBLIC", "SYNTHETIC", "OUTPUT", "MARKER"))
policy = os.environ["OUTPUT_POLICY"]
run_id = os.environ["RUN_ID"]
if policy not in ("disabled", "redact"):
    raise SystemExit("unknown fixture output policy")
value = "[REDACTED]" if policy == "redact" else marker
root = pathlib.Path("/out") / run_id
root.mkdir(parents=True, exist_ok=True)
for kind, filename in (("artifact", "artifact.json"), ("checkpoint", "checkpoint.json"), ("pipeline-metadata", "pipeline-metadata.json")):
    record = {"schema": "saf.fixture.output.v1", "pipeline": "synthetic-training", "run_id": run_id, "output_kind": kind, "sample": value}
    (root / filename).write_text(json.dumps(record, sort_keys=True) + "\n")
print(json.dumps({"schema": "saf.fixture.training-log.v1", "pipeline": "synthetic-training", "run_id": run_id, "event": "sample_processed", "sample": value}, sort_keys=True), flush=True)
'''
READBACK_WORKLOAD = r'''import os, pathlib
root = pathlib.Path("/out") / os.environ["RUN_ID"]
for filename in ("artifact.json", "checkpoint.json", "pipeline-metadata.json"):
    print((root / filename).read_text().strip(), flush=True)
'''


def _marker():
    return "-".join(("PUBLIC", "SYNTHETIC", "OUTPUT", "MARKER"))


def _private_prefix(lab):
    env = dict(lab.env)
    for key in ("KUBECTL_EXTERNAL_DIFF", "KUBECTL_PLUGINS_CALLER",
                "KUBECTL_PLUGINS_CURRENT_NAMESPACE"):
        env.pop(key, None)
    env["KUBECTL_KUBERC"] = "false"
    return env, ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
                 f"kind-{lab.cluster}", "--namespace", "saf-test",
                 "--request-timeout=25s"]


def _private(args, *, env):
    return subprocess.run(args, env=env, capture_output=True, text=True, timeout=30)


OBSERVATION_POD = "saf-0403-output-observer"


def _observer(lab):
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": OBSERVATION_POD},
                "spec": {"restartPolicy": "Never", "activeDeadlineSeconds": 240,
                         "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "fsGroup": 1000,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [{"name": "observer", "image": IMAGE,
                                         "command": ["python", "-c", "from time import sleep; sleep(230)"],
                                         "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                                       "limits": {"cpu": "100m", "memory": "96Mi"}},
                                         "securityContext": {"allowPrivilegeEscalation": False,
                                                             "readOnlyRootFilesystem": True,
                                                             "capabilities": {"drop": ["ALL"]}},
                                         "volumeMounts": [{"name": "outputs", "mountPath": "/out", "readOnly": True}]}],
                         "volumes": [{"name": "outputs", "persistentVolumeClaim": {"claimName": PVC}}]}})
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{OBSERVATION_POD}", "--timeout=60s", timeout=70)


def _outputs(lab, run_id):
    env, prefix = _private_prefix(lab)
    outputs = {}
    for kind in SINKS:
        result = _private(prefix + ["exec", OBSERVATION_POD, "--", "cat", f"/out/{run_id}/{kind}.json"], env=env)
        if result.returncode:
            lab.block("Persisted fixture output could not be read; output was not retained")
        try:
            outputs[kind] = json.loads(result.stdout)
        except json.JSONDecodeError:
            lab.block("Persisted fixture output was malformed; output was not retained")
    logs = _private(prefix + ["logs", f"job/saf-0403-{run_id}"], env=env)
    if logs.returncode:
        lab.block("Fixture Job logs could not be read; output was not retained")
    try:
        log_record = json.loads(logs.stdout)
    except json.JSONDecodeError:
        lab.block("Fixture Job log was malformed; output was not retained")
    return log_record, outputs


def _wait_job(lab, run_id, expected):
    name = f"saf-0403-{run_id}"
    deadline = monotonic() + 105
    while monotonic() < deadline:
        result = lab.kubectl("get", "job", name, "-o", "json", timeout=15)
        conditions = (json.loads(result.stdout).get("status") or {}).get("conditions") or []
        terminal = {item["type"] for item in conditions if item.get("status") == "True"}
        if expected in terminal:
            return
        if terminal & {"Complete", "Failed"}:
            lab.block(f"Output fixture Job {name} reached an unexpected terminal condition")
        sleep(1)
    lab.kubectl("get", "pods", "-l", f"job-name={name}", "-o", "json", allow_failure=True, timeout=15)
    lab.block(f"Output fixture Job {name} did not finish within its allowed wait")


def _job(run_id, policy):
    script = WORKLOAD
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": f"saf-0403-{run_id}", "namespace": "saf-test"},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
                 "ttlSecondsAfterFinished": 300,
                 "template": {"metadata": {"labels": {"app": "saf-0403-output"}},
                              "spec": {"restartPolicy": "Never",
                                       "automountServiceAccountToken": False,
                                       "securityContext": {"runAsNonRoot": True,
                                                           "runAsUser": 1000,
                                                           "fsGroup": 1000,
                                                           "seccompProfile": {"type": "RuntimeDefault"}},
                                       "containers": [{"name": "fixture", "image": IMAGE,
                                                       "imagePullPolicy": "IfNotPresent",
                                                       "command": ["python", "-c", script],
                                                       "env": [{"name": "OUTPUT_POLICY", "value": policy},
                                                               {"name": "RUN_ID", "value": run_id}],
                                                       "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                                                     "limits": {"cpu": "100m", "memory": "96Mi"}},
                                                       "securityContext": {"allowPrivilegeEscalation": False,
                                                                           "readOnlyRootFilesystem": True,
                                                                           "capabilities": {"drop": ["ALL"]}},
                                                       "volumeMounts": [{"name": "outputs", "mountPath": "/out"}]}],
                                       "volumes": [{"name": "outputs", "persistentVolumeClaim": {"claimName": PVC}}]}}}}


def _reader_job(run_id):
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": f"saf-0403-read-{run_id}", "namespace": "saf-test"},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
                 "ttlSecondsAfterFinished": 300,
                 "template": {"metadata": {"labels": {"app": "saf-0403-readback"}},
                              "spec": {"restartPolicy": "Never",
                                       "automountServiceAccountToken": False,
                                       "securityContext": {"runAsNonRoot": True,
                                                           "runAsUser": 1000,
                                                           "fsGroup": 1000,
                                                           "seccompProfile": {"type": "RuntimeDefault"}},
                                       "containers": [{"name": "readback", "image": IMAGE,
                                                       "imagePullPolicy": "IfNotPresent",
                                                       "command": ["python", "-c", READBACK_WORKLOAD],
                                                       "env": [{"name": "RUN_ID", "value": run_id}],
                                                       "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                                                     "limits": {"cpu": "100m", "memory": "96Mi"}},
                                                       "securityContext": {"allowPrivilegeEscalation": False,
                                                                           "readOnlyRootFilesystem": True,
                                                                           "capabilities": {"drop": ["ALL"]}},
                                                       "volumeMounts": [{"name": "outputs", "mountPath": "/out",
                                                                         "readOnly": True}]}],
                                       "volumes": [{"name": "outputs", "persistentVolumeClaim": {"claimName": PVC}}]}}}}


def _pipeline_observations(lab):
    marker = _marker()
    lab.create({"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                "metadata": {"name": PVC, "namespace": "saf-test"},
                "spec": {"accessModes": ["ReadWriteOnce"],
                         "resources": {"requests": {"storage": "32Mi"}}}})
    baseline_id, protected_id, invalid_id = "baseline", "protected", "invalid"
    for run_id, policy in ((baseline_id, "disabled"), (protected_id, "redact"), (invalid_id, "invalid")):
        lab.create(_job(run_id, policy))
    _wait_job(lab, baseline_id, "Complete")
    _wait_job(lab, protected_id, "Complete")
    _wait_job(lab, invalid_id, "Failed")
    claim = json.loads(lab.kubectl("get", "pvc", PVC, "-o", "json", timeout=15).stdout)
    persisted = claim.get("status", {}).get("phase") == "Bound" and bool(claim["spec"].get("volumeName"))
    _observer(lab)
    baseline_log, baseline_sinks = _outputs(lab, baseline_id)
    baseline_matches = (baseline_log.get("sample") == marker
                        and all(baseline_sinks[kind].get("sample") == marker for kind in SINKS))
    lab.check("red", "The disabled-mode Job exposes the same public marker in its actual log and each persisted structured sink",
              baseline_matches,
              {"job_log_marker_present": baseline_log.get("sample") == marker,
               "artifact_marker_present": baseline_sinks["artifact"].get("sample") == marker,
               "checkpoint_marker_present": baseline_sinks["checkpoint"].get("sample") == marker,
               "pipeline_metadata_marker_present": baseline_sinks["pipeline-metadata"].get("sample") == marker})

    protected_log, protected_sinks = _outputs(lab, protected_id)
    marker_absent = (marker not in json.dumps(protected_log)
                     and all(marker not in json.dumps(protected_sinks[kind]) for kind in SINKS))
    fields_preserved = (protected_log.get("schema") == "saf.fixture.training-log.v1"
                        and protected_log.get("pipeline") == "synthetic-training"
                        and protected_log.get("run_id") == protected_id
                        and protected_log.get("event") == "sample_processed"
                        and protected_log.get("sample") == REDACTED
                        and all(protected_sinks[kind].get("schema") == "saf.fixture.output.v1"
                                and protected_sinks[kind].get("pipeline") == "synthetic-training"
                                and protected_sinks[kind].get("run_id") == protected_id
                                and protected_sinks[kind].get("output_kind") == kind
                                and protected_sinks[kind].get("sample") == REDACTED
                                for kind in SINKS))
    lab.check("green", "The explicit structured output policy redacts the marker while retaining useful non-sensitive fields",
              marker_absent and fields_preserved,
              {"marker_absent_from_job_log": marker not in json.dumps(protected_log),
               "marker_absent_from_persisted_sinks": all(marker not in json.dumps(protected_sinks[kind]) for kind in SINKS),
               "non_sensitive_fields_preserved": fields_preserved,
               "sinks_read_back": len(protected_sinks)})
    lab.check("positive", "An independent read-only Pod retrieves the three files after both output Jobs complete",
              persisted and len(protected_sinks) == 3,
              {"both_jobs_completed": True, "claim_bound": persisted, "persisted_sink_count": len(protected_sinks)})
    env, prefix = _private_prefix(lab)
    invalid_log = _private(prefix + ["logs", f"job/saf-0403-{invalid_id}"], env=env)
    invalid_dir = _private(prefix + ["exec", OBSERVATION_POD, "--", "python", "-c",
                                     "from pathlib import Path; print(Path('/out/invalid').exists())"], env=env)
    refused = invalid_log.returncode == 0 and invalid_log.stdout.strip() == "unknown fixture output policy"
    directory_absent = invalid_dir.returncode == 0 and invalid_dir.stdout.strip() == "False"
    lab.check("green", "An invalid policy fails before emitting a sample or creating persisted output",
              refused and directory_absent,
              {"invalid_policy_refused": refused, "output_directory_absent": directory_absent})


def run(lab):
    # Published kubectl diff observations retained verbatim in behavior.
    env = dict(lab.env)
    for key in ("KUBECTL_EXTERNAL_DIFF", "KUBECTL_PLUGINS_CALLER", "KUBECTL_PLUGINS_CURRENT_NAMESPACE"):
        env.pop(key, None)
    env["KUBECTL_KUBERC"] = "false"
    prefix = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
              f"kind-{lab.cluster}", "--namespace", "saf-test", "--request-timeout=20s"]

    def private(args, payload=None):
        return subprocess.run(prefix + args, input=payload, env=env, capture_output=True,
                              text=True, timeout=30)

    client = private(["version", "--client", "-o", "json"])
    if client.returncode:
        lab.block("Unable to determine kubectl version")
    version = json.loads(client.stdout)["clientVersion"]["gitVersion"]
    if version != "v1.36.1":
        lab.block(f"The exact client for this case is v1.36.1; found {version}")

    encoded = [base64.b64encode(value.encode()).decode() for value in (DIFF_BEFORE, DIFF_AFTER)]

    def manifest(value):
        return json.dumps({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                           "metadata": {"name": DIFF_NAME, "namespace": "saf-test"},
                           "data": {"marker": value}})

    options = ["--server-side", "--field-manager", FIELD_MANAGER, "-f", "-"]
    created = private(["apply", *options, "-o", "name"], manifest(encoded[0]))
    lab.check("positive", "The synthetic fixture object was accepted",
              created.returncode == 0 and created.stdout.strip() == f"secret/{DIFF_NAME}",
              {"accepted": created.returncode == 0, "client": version})
    revision_args = ["get", f"secret/{DIFF_NAME}", "-o", "jsonpath={.metadata.resourceVersion}"]
    before = private(revision_args)
    lab.check("positive", "The fixture has a persisted resource version",
              before.returncode == 0 and before.stdout.strip().isdigit(),
              {"resource_version_present": before.stdout.strip().isdigit()})

    for phase, extra, should_show in (("red", ["--show-secrets=true"], True),
                                      ("green", [], False),
                                      ("green", ["--show-secrets=false"], False)):
        result = private(["diff", *options, *extra], manifest(encoded[1]))
        visible = [value in result.stdout + result.stderr for value in encoded]
        plain_visible = any(value in result.stdout + result.stderr for value in (DIFF_BEFORE, DIFF_AFTER))
        actual_diff = result.returncode == 1
        masked_change = all(mask in result.stdout for mask in ("*** (before)", "*** (after)"))
        lab.check(phase, f"Client reports a diff with marker values {'visible' if should_show else 'masked'}",
                  actual_diff and visible == [should_show, should_show]
                  and not plain_visible and (should_show or masked_change),
                  {"diff_detected": actual_diff, "before_visible": visible[0],
                   "after_visible": visible[1], "plain_values_visible": plain_visible,
                   "masked_change": masked_change})
    after = private(revision_args)
    lab.check("positive", "Comparisons leave the fixture resource version unchanged",
              after.returncode == 0 and before.stdout == after.stdout,
              {"same_revision": before.stdout == after.stdout})
    _pipeline_observations(lab)
