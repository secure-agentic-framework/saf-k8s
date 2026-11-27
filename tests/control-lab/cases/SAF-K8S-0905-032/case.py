"""SAF-K8S-0905-032: inert model-format allowlist lab case."""
import json
import hashlib
import base64
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
PYPI_FILES = "https://files.pythonhosted.org/packages/"
SAFE_TENSORS_WHEELS = {
    "arm64": (
        "2a/43/bf38443278eab4b1be1fce2931e2b012ad9cb7df52ada751d0aab8f7659a/",
        "aarch64", "87eec7ffed2b809f05a398a8becb7d013f19f7837cd15d9748580d6cf30dbaf4",
    ),
    "amd64": (
        "27/43/41c1621732edd934d868a00d1b891584c892a7b62a9aab82ea5a0a5623ee/",
        "x86_64", "8e080062fcde23be189565e1c3305d16751a218ecf9412c8601e64204eb6f846",
    ),
}
EXPECTED_SAFETENSORS_DIGEST = "1fa6bcfde3b5c5b07623e9b282bc92f89dc8ae9e2ebfd9d2097b1d6e1aa76548"
EXPECTED_PRIMITIVE_PICKLE_SHA256 = "06d302a110b5a89f9282c390a7c6256905840c30d98534642377242191a79a6e"

SCOPE = (
    "Runs one fixture-owned Kubernetes Job in the precreated saf-test namespace. "
    "Inputs are fixed inert bytes and a tiny F32[2] SafeTensors vector. Red records a permissive "
    "decision reaching only a counted stub; green denies those bytes before loader invocation; "
    "the original narrow fixture and JSON checks remain. An additional path verifies the official "
    "digest-pinned upstream safetensors 0.8.0 parser reads only the exact approved digest and "
    "that wrong-format, unapproved-digest, and mislabeled inert candidates cause zero parser calls. "
    "The worker is tokenless, has read-only code/package mounts, and extracts only to a bounded "
    "memory-backed volume. This does not test production model loading, PyTorch, GPU, hostile "
    "payloads, general format compatibility, other architectures, or 0905-033 structure/metadata checks."
    " One immutable fixture contains only primitive serialized data. The explicit pickle format is "
    "denied before dispatch. The Job reports its exact artifact digest, passive inspection and zero loader calls."
)


def _job(lab):
    name = "model-format-policy"
    worker = {"apiVersion": "v1", "kind": "ConfigMap",
              "metadata": {"name": "model-format-worker"},
              "immutable": True, "data": {"worker.py": (HERE / "worker.py").read_text()}}
    lab.create(worker)
    pickle_bytes = (HERE / "fixtures" / "primitive-only.pickle").read_bytes()
    if hashlib.sha256(pickle_bytes).hexdigest() != EXPECTED_PRIMITIVE_PICKLE_SHA256:
        lab.block("Primitive-only pickle fixture does not match its pinned digest")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "model-format-primitive-pickle"}, "immutable": True,
                "binaryData": {"primitive-only.pickle": base64.b64encode(pickle_bytes).decode("ascii")}})
    arch = lab.kubectl("get", "nodes", "-o",
                       "jsonpath={.items[0].status.nodeInfo.architecture}").stdout.strip()
    if arch not in SAFE_TENSORS_WHEELS:
        lab.block("No pinned SafeTensors wheel for the observed node architecture")
    wheel_prefix, machine, wheel_digest = SAFE_TENSORS_WHEELS[arch]
    wheel_name = f"safetensors-0.8.0-cp310-abi3-musllinux_1_2_{machine}.whl"
    wheel = lab.kubeconfig.parent / wheel_name
    try:
        lab.command("curl", "--fail", "--silent", "--show-error", "--max-time", "40",
                    "--output", str(wheel), PYPI_FILES + wheel_prefix + wheel_name,
                    timeout=45)
        if hashlib.sha256(wheel.read_bytes()).hexdigest() != wheel_digest:
            lab.block("Official SafeTensors wheel does not match the pinned package digest")
        lab.kubectl("create", "configmap", "model-format-native-wheel",
                    "--from-file=safetensors.whl=" + str(wheel), "-o", "name")
    finally:
        wheel.unlink(missing_ok=True)
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 60,
                 "template": {"metadata": {"labels": {"app": name}}, "spec": {
                     "restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                         "runAsGroup": 1000, "fsGroup": 1000,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "fixture", "image": PYTHON,
                                     "imagePullPolicy": "IfNotPresent",
                                     "command": ["python", "-B", "/worker/worker.py"],
                                     "env": [{"name": "SAF_EXPECTED_MACHINE", "value": machine},
                                             {"name": "SAF_EXPECTED_WHEEL_SHA256",
                                              "value": wheel_digest}],
                                     "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                   "limits": {"cpu": "100m", "memory": "64Mi"}},
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}},
                                     "volumeMounts": [{"name": "worker", "mountPath": "/worker",
                                                       "readOnly": True},
                                                      {"name": "wheel", "mountPath": "/wheel",
                                                       "readOnly": True},
                                                      {"name": "runtime", "mountPath": "/runtime"},
                                                      {"name": "pickle", "mountPath": "/fixture", "readOnly": True}]}],
                     "volumes": [{"name": "worker", "configMap": {
                         "name": "model-format-worker", "defaultMode": 292}},
                         {"name": "wheel", "configMap": {
                             "name": "model-format-native-wheel", "defaultMode": 292}},
                         {"name": "runtime", "emptyDir": {
                             "medium": "Memory", "sizeLimit": "12Mi"}},
                         {"name": "pickle", "configMap": {
                             "name": "model-format-primitive-pickle", "defaultMode": 292}}]}}}})
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        states = {condition["type"] for condition in job.get("status", {}).get("conditions", [])
                  if condition.get("status") == "True"}
        if "Failed" in states:
            lab.kubectl("logs", "job/" + name, allow_failure=True)
            lab.block("Fixture Job failed: " + name)
        if "Complete" in states:
            log = lab.kubectl("logs", "job/" + name).stdout
            try:
                report = json.loads(log)
                report["node_arch"] = arch
                return report
            except json.JSONDecodeError:
                lab.block("Fixture Job did not emit its stable JSON result: " + name)
        time.sleep(0.5)
    lab.block("Fixture Job timed out: " + name)


def check_observations(lab, observations):
    permissive = observations["permissive"]
    legacy = {"declared_format": "legacy-inert", "sha256": permissive["sha256"]}
    counters = {"deny_count": 0, "loader_calls": 0, "stub_calls": 0, "values_read": 0}
    lab.check("red", "The permissive policy routes the fixed inert representation to a counted stub",
              permissive == {**legacy, "status": "STUB_ONLY", "counters": {**counters, "stub_calls": 1}},
              permissive)

    restricted = observations["restricted"]
    lab.check("green", "The allowlist denies the same input before invoking any loader",
              restricted == {**legacy, "status": "DENY_FORMAT", "counters": {**counters, "deny_count": 1}},
              restricted)

    approved = observations["approved"]
    lab.check("positive", "The same allowlist routes approved bytes to the loader and returns the exact fixture values",
              approved["declared_format"] == "safetensors" and approved["status"] == "SAFE_LOADED"
              and approved["sha256"] != legacy["sha256"] and approved["values"] == [1.25, -2.5]
              and approved["counters"] == {**counters, "loader_calls": 1, "values_read": 2},
              approved)

    ordinary = observations["declarative_json"]
    good = ordinary["approved"]
    approved_digest = "50e0d5c3ffb448eb7435ed99a8cb6118438fc2765248b459d313e493ed5a5473"
    unapproved_digest = "d7f330b264a1c639e2b008011b7956c737b9b3271ecee68f48d73336760e5a53"
    lab.check("positive", "Exact allowlisted JSON data digest is admitted and parsed by the standard declarative loader",
              good == {"declared_format": "json-data", "sha256": approved_digest,
                       "admitted": True, "loader_sha256": approved_digest,
                       "status": "JSON_DATA_LOADED", "values": [1.25, -2.5],
                       "counters": {"deny_count": 0, "loader_calls": 1, "values_read": 2}},
              good)
    wrong_format = ordinary["wrong_format"]
    lab.check("green", "A wrong format label is denied before the JSON data loader",
              wrong_format["sha256"] == approved_digest and wrong_format["declared_format"] == "legacy-inert"
              and wrong_format["admitted"] is False and wrong_format["loader_sha256"] is None
              and wrong_format["status"] == "DENY_BEFORE_LOADER"
              and wrong_format["counters"] == {"deny_count": 1, "loader_calls": 0, "values_read": 0},
              wrong_format)
    wrong_digest = ordinary["unapproved_digest"]
    lab.check("green", "An unapproved JSON digest is denied before the JSON data loader",
              wrong_digest["sha256"] == unapproved_digest and wrong_digest["declared_format"] == "json-data"
              and wrong_digest["admitted"] is False and wrong_digest["loader_sha256"] is None
              and wrong_digest["status"] == "DENY_BEFORE_LOADER"
              and wrong_digest["counters"] == {"deny_count": 1, "loader_calls": 0, "values_read": 0},
              wrong_digest)

    mislabeled = observations["mislabeled"]
    lab.check("green", "Mislabeling the same inert bytes does not cause the approved parser to consume model values",
              mislabeled == {"declared_format": "safetensors", "sha256": legacy["sha256"],
                             "status": "REJECTED_BEFORE_VALUES",
                             "counters": {**counters, "loader_calls": 1}},
              mislabeled)

    native = observations["native_safetensors"]
    arch = observations["node_arch"]
    expected_machine = SAFE_TENSORS_WHEELS[arch][1]
    wheel_digest = SAFE_TENSORS_WHEELS[arch][2]
    actual = native["outcomes"]
    lab.check("positive", "Pinned upstream SafeTensors parses the independently digest-bound inert vector; denied paths make no parser calls",
              native["library"] == "0.8.0" and native["machine"] == expected_machine
              and native["expected_machine"] == expected_machine
              and native["wheel_sha256"] == wheel_digest
              and actual["approved"] == {
                  "declared_format": "safetensors", "sha256": EXPECTED_SAFETENSORS_DIGEST,
                  "status": "NATIVE_LOADED", "native_calls": 1, "native_call_delta": 1,
                  "tensor_name": "weight",
                  "dtype": "F32", "shape": [2], "values": [1.25, -2.5]}
              and all(actual[name]["status"] == "DENY_BEFORE_NATIVE"
                      and actual[name]["native_call_delta"] == 0
                      for name in ("wrong_format", "unapproved_digest", "mislabeled_inert")),
              native)

    primitive = observations["primitive_pickle"]
    lab.check("green", "Primitive-only pickle representation is denied before loader dispatch",
              primitive == {
                  "format": "pickle", "sha256": EXPECTED_PRIMITIVE_PICKLE_SHA256,
                  "status": "DENY_BEFORE_LOADER",
                  "opcodes": ["PROTO", "FRAME", "EMPTY_DICT", "MEMOIZE", "SHORT_BINUNICODE",
                              "MEMOIZE", "EMPTY_LIST", "MEMOIZE", "MARK", "BINFLOAT", "BINFLOAT",
                              "APPENDS", "SETITEM", "STOP"],
                  "counters": {"deny_count": 1, "loader_dispatch_attempts": 0,
                               "loader_calls": 0, "values_read": 0}},
              primitive)


def run(lab):
    observations = _job(lab)
    (lab.evidence / "model-format-allowlist.json").write_text(
        json.dumps(observations, indent=2, sort_keys=True) + "\n")
    check_observations(lab, observations)
