"""Observe a narrow keyed serving-output marker on real isolated Kind workloads."""
import importlib.util
import json
import secrets
from pathlib import Path

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
BASELINE = "fixture-watermark-baseline"
GOVERNED = "fixture-watermark-marked"
DETECTOR = "fixture-watermark-detector"
CODE = "fixture-watermark-code"
KEY = "fixture-watermark-key"
KIND_MARK = "keyed_evidence_threshold_met"
SCOPE = (
    "Two live services emit fixed benign text with and without the configured keyed marker. "
    "A separate detector workload verifies ten template positions with the authorized key. "
    "The comparator handles one predefined normalization and rejects one unrelated document."
)


def launch(lab, image, name, mode=None, *, mount_key=False):
    mounts = [{"name": "code", "mountPath": "/fixture", "readOnly": True}]
    volumes = [{"name": "code", "configMap": {"name": CODE}}]
    if mount_key:
        mounts.append({"name": "marker", "mountPath": "/verification", "readOnly": True})
        volumes.append({"name": "marker", "secret": {"secretName": KEY, "defaultMode": 0o440}})
    command = ["python", "/fixture/watermark_fixture.py", mode] if mode else ["sleep", "300"]
    unit = container("fixture", image=image, imagePullPolicy="Never", command=command, volumeMounts=mounts)
    resource = pod(name, [unit], automountServiceAccountToken=False, volumes=volumes,
                   securityContext={"fsGroup": 65534})
    resource["metadata"]["labels"] = {"app": name}
    if mode:
        unit["readinessProbe"] = {"tcpSocket": {"port": 8080}, "periodSeconds": 1}
    lab.create(resource)
    if mode:
        lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                    "spec": {"selector": {"app": name}, "ports": [{"port": 8080}]}})


def observe(lab, service):
    result = lab.kubectl("exec", DETECTOR, "--", "python", "/fixture/watermark_fixture.py",
                         "verify", service, timeout=18)
    return json.loads(result.stdout)


def run(lab):
    helper_path = HERE.parent / "SAF-K8S-0908-001" / "case.py"
    spec = importlib.util.spec_from_file_location("fixture_watermark_runtime", helper_path)
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    image = runtime.load_runtime(lab)
    marker = lab.kubeconfig.parent / "fixture-marker"
    marker.write_bytes(secrets.token_bytes(32))
    lab.kubectl("create", "secret", "generic", KEY, f"--from-file=marker={marker}", "-o", "name")
    marker.unlink()
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CODE},
                "immutable": True, "data": {
                    "watermark_fixture.py": (HERE / "watermark_fixture.py").read_text()}})
    launch(lab, image, BASELINE, "unmarked")
    launch(lab, image, GOVERNED, "marked", mount_key=True)
    launch(lab, image, DETECTOR, mount_key=True)
    for name in (BASELINE, GOVERNED, DETECTOR):
        ready(lab, name)

    baseline = observe(lab, BASELINE)
    marked = observe(lab, GOVERNED)
    red = {"baseline_serves_unmarked_text": baseline["served_text"] == {
        "detected": False, "reason": "outside_fixed_fixture_grammar", "positions": 0, "matches": 0}}
    lab.check("red", "The unchanged unmarked baseline does not contain the fixture marker",
              all(red.values()), red)
    green = {"separate_detector_observes_marked_output": marked["served_text"] == {
        "detected": True, "reason": KIND_MARK, "positions": 10, "matches": 10}}
    lab.check("green", "The separate detector verifies governed serving output",
              all(green.values()), green)
    positive = {
        "defined_case_and_punctuation_normalization_preserves_marker":
            marked["normalized_text"] == marked["served_text"],
        "separate_unrelated_public_fixture_remains_unmarked":
            marked["benign_unrelated_text"]["detected"] is False,
    }
    lab.check("positive", "The approved normalization preserves the marker and unrelated text stays unmarked",
              all(positive.values()), positive)
    (lab.evidence / "watermark-observations.json").write_text(json.dumps(
        {"baseline": baseline, "marked": marked, "checks": [red, green, positive],
         "scope": "fixed synthetic text template only"}, indent=2, sort_keys=True) + "\n")
