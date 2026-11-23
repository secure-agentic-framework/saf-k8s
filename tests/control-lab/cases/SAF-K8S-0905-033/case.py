"""Check a bounded model preflight against the official native SafeTensors loader."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
NAME = "fixture-model-preflight"
CODE = NAME + "-code"
WHEEL = NAME + "-wheel"
FILE_HOST = "https://files.pythonhosted.org/packages/"
PLATFORMS = {
    "arm64": (
        "2a/43/bf38443278eab4b1be1fce2931e2b012ad9cb7df52ada751d0aab8f7659a/",
        "aarch64", "87eec7ffed2b809f05a398a8becb7d013f19f7837cd15d9748580d6cf30dbaf4",
    ),
    "amd64": (
        "27/43/41c1621732edd934d868a00d1b891584c892a7b62a9aab82ea5a0a5623ee/",
        "x86_64", "8e080062fcde23be189565e1c3305d16751a218ecf9412c8601e64204eb6f846",
    ),
}
SCOPE = (
    "A live Kind Pod loads an official pinned SafeTensors library. The unchecked baseline loads a "
    "valid integer tensor that violates the case's F32 policy. The bounded case preflight rejects "
    "that tensor and a fixed wrong-length F32 file before calling the native tensor loader. "
    "The approved four-weight payload loads with exact values. This checks only the locked schema."
)


def run(lab):
    path = HERE.parent / "SAF-K8S-0908-001" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_preload_runtime", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    image = module.load_runtime(lab)
    arch = lab.kubectl("get", "nodes", "-o", "jsonpath={.items[0].status.nodeInfo.architecture}").stdout.strip()
    if arch not in PLATFORMS:
        lab.block("The pinned wheel is unavailable for the detected node architecture")
    folder, machine, checksum = PLATFORMS[arch]
    name = f"safetensors-0.8.0-cp310-abi3-musllinux_1_2_{machine}.whl"
    wheel = lab.kubeconfig.parent / name
    lab.command("curl", "--fail", "--silent", "--show-error", "--max-time", "40", "--output",
                str(wheel), FILE_HOST + folder + name, timeout=45)
    if sha256(wheel.read_bytes()).hexdigest() != checksum:
        lab.block("The SafeTensors wheel differs from the pinned package digest")
    lab.kubectl("create", "configmap", WHEEL, "--from-file=safetensors.whl=" + str(wheel), "-o", "name")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CODE},
                "immutable": True, "data": {"preload_fixture.py": (HERE / "preload_fixture.py").read_text()}})
    workload = container("validator", image=image, imagePullPolicy="Never",
                         command=["python", "/fixture/preload_fixture.py"], volumeMounts=[
                             {"name": "code", "mountPath": "/fixture", "readOnly": True},
                             {"name": "wheel", "mountPath": "/wheel", "readOnly": True},
                         ])
    lab.create(pod(NAME, [workload], automountServiceAccountToken=False, volumes=[
        {"name": "code", "configMap": {"name": CODE}}, {"name": "wheel", "configMap": {"name": WHEEL}},
    ]))
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{NAME}",
                "--timeout=80s", timeout=90)
    report = json.loads(lab.kubectl("logs", f"pod/{NAME}").stdout)
    rows = report["outcomes"]
    lab.check("red", "A valid but unapproved dtype reaches the native loader without preflight",
              rows["baseline-wrong-dtype"] == {"decision": "loaded", "dtype": "I32", "shape": [2, 2],
                                              "weights": [1, 2, 3, 4], "native_calls": 1},
              rows["baseline-wrong-dtype"])
    gate = {name: rows["governed-" + name] for name in ("wrong-dtype", "wrong-length")}
    lab.check("green", "The bounded preflight refuses both input mismatches before the load call",
              gate == {"wrong-dtype": {"decision": "denied", "reason": "dtype-policy", "native_calls": 0},
                       "wrong-length": {"decision": "denied", "reason": "payload-length", "native_calls": 0}}, gate)
    positive = rows["governed-approved"]
    lab.check("positive", "The pinned native loader returns the exact approved tensor",
              report["library"] == "0.8.0" and positive == {
                  "decision": "loaded", "dtype": "F32", "shape": [2, 2],
                  "weights": [0.25, -0.5, 1.0, 2.0], "native_calls": 1,
              }, {"wheel_sha256": checksum, "library": report["library"], "result": positive})
    (lab.evidence / "preload-validation-observations.json").write_text(
        json.dumps({**report, "wheel_sha256": checksum}, sort_keys=True, indent=2) + "\n")
