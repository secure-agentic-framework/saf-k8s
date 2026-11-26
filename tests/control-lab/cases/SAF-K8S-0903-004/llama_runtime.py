"""Run the pinned llama.cpp CPU serving witness in a disposable cluster."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

HERE = Path(__file__).resolve().parent
SERVER = "saf-llama-real"
CLIENT = "saf-llama-client"
CLIENT_CONFIG = "saf-llama-client-files"
SERVER_IMAGES = {
    "arm64": "ghcr.io/ggml-org/llama.cpp:server-b9519@sha256:dddfe5993e7e8e011ad419f6d451e4c66460fbd6679cac436552ae449fd6a1f8",
    "amd64": "ghcr.io/ggml-org/llama.cpp:server-b9519@sha256:abaf7899e16b638411096f6db42563dffa876119037458b7986f2a6bde3df41e",
}
PYTHON_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
MODEL_URL = "https://huggingface.co/ggml-org/stories15M_MOE/resolve/b6dd737497465570b5f5e962dbc9d9454ed1e0eb/stories15M_MOE-F16.gguf"
MODEL_NAME = "stories15M_MOE-F16.gguf"
MODEL_SHA256 = "1240dfc1957df9f3550dd6c1d9e64b466fc2f452d8bc34bd4e45e1a1e2ca6055"
DERIVED_IMAGE_TAG = "saf-k8s-llama-0903-004"
PORT = 8080


def _build_and_load(lab):
    node = json.loads(lab.kubectl("get", "node", lab.cluster + "-control-plane", "-o", "json").stdout)
    architecture = node["status"]["nodeInfo"]["architecture"]
    base = SERVER_IMAGES.get(architecture)
    if base is None:
        lab.block(f"The pinned CPU serving fixture has no reviewed image for {architecture}")
    image = f"{DERIVED_IMAGE_TAG}:{lab.cluster}"
    with tempfile.TemporaryDirectory(prefix="saf-0903-004-llama-build-") as temporary:
        build = Path(temporary)
        model = build / MODEL_NAME
        lab.command("curl", "-fsSL", "--proto", "=https", "--proto-redir", "=https",
                    "--max-time", "90", "--max-filesize", "80000000", "--retry", "1",
                    "--output", str(model), MODEL_URL, timeout=100)
        observed_sha256 = hashlib.sha256(model.read_bytes()).hexdigest()
        if model.stat().st_size != 73466432 or observed_sha256 != MODEL_SHA256:
            lab.block("The host-fetched tiny Stories model did not match its reviewed size and digest")
        shutil.copyfile(HERE / "Dockerfile.llama", build / "Dockerfile.llama")
        lab.command("docker", "build", "--network=none", "--platform", f"linux/{architecture}",
                    "--build-arg", f"SERVER_IMAGE={base}", "-f", str(build / "Dockerfile.llama"),
                    "-t", image, str(build), timeout=180)
        try:
            image_id = lab.command("docker", "image", "inspect", "--format={{.Id}}", image,
                                   timeout=20).stdout.strip()
            lab.command("kind", "load", "docker-image", image, "--name", lab.cluster, timeout=120)
        finally:
            lab.command("docker", "image", "rm", image, allow_failure=True, timeout=25)
    return image, {"node_architecture": architecture, "derived_image_id": image_id,
                   "base_image": base, "model_url": MODEL_URL, "model_sha256": observed_sha256,
                   "model_bytes": 73466432, "llama_release": "b9519"}


def _server_pod(image):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": SERVER, "labels": {"fixture": SERVER}},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "runAsGroup": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "llama-server", "image": image, "imagePullPolicy": "Never",
                "args": ["--model", "/models/stories15M_MOE-F16.gguf",
                         "--alias", "stories15m-moe", "--host", "0.0.0.0", "--port", str(PORT),
                         "--ctx-size", "256", "--n-predict", "4", "--seed", "42",
                         "--temp", "0", "--threads", "1", "--parallel", "1", "--n-gpu-layers", "0"],
                "ports": [{"name": "http", "containerPort": PORT, "protocol": "TCP"}],
                "startupProbe": {"httpGet": {"path": "/health", "port": "http"},
                                 "periodSeconds": 2, "timeoutSeconds": 2,
                                 "failureThreshold": 90},
                "readinessProbe": {"httpGet": {"path": "/health", "port": "http"},
                                   "periodSeconds": 2, "timeoutSeconds": 2,
                                   "failureThreshold": 3},
                "resources": {"requests": {"cpu": "250m", "memory": "384Mi",
                                             "ephemeral-storage": "32Mi"},
                              "limits": {"cpu": "1500m", "memory": "768Mi",
                                         "ephemeral-storage": "96Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
            }],
        },
    }


def _client_pod():
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": CLIENT, "labels": {"fixture": CLIENT}},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "volumes": [{"name": "client-files", "configMap": {"name": CLIENT_CONFIG}}],
            "containers": [{
                "name": "client", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "-c", "import time; time.sleep(180)"],
                "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                              "limits": {"cpu": "200m", "memory": "96Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "client-files", "mountPath": "/fixture",
                                  "readOnly": True}],
            }],
        },
    }


def run(lab):
    """Append after all existing 0903-004 checks; add two native-engine observations."""
    image, provenance = _build_and_load(lab)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": CLIENT_CONFIG}, "immutable": True,
                "data": {"llama_client.py": (HERE / "llama_client.py").read_text()}})
    lab.create(_server_pod(image))
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + SERVER,
                "--timeout=75s", timeout=85)
    server = json.loads(lab.kubectl("get", "pod", SERVER, "-o", "json").stdout)
    pod_ip = server["status"].get("podIP")
    image_id = server["status"]["containerStatuses"][0]["imageID"]
    if not pod_ip or not image_id:
        lab.block("The real llama server Pod has no observed IP or runtime image ID")
    if server["spec"].get("automountServiceAccountToken") is not False:
        lab.block("The real llama server did not preserve the reviewed tokenless spec")
    provenance.update({"server_pod_uid": server["metadata"]["uid"],
                       "server_pod_ip": pod_ip, "runtime_image_id": image_id,
                       "service_created": False, "service_account_token_mounted": False})
    lab.create(_client_pod())
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + CLIENT,
                "--timeout=60s", timeout=70)
    result = lab.kubectl("exec", "pod/" + CLIENT, "--", "python", "-B",
                         "/fixture/llama_client.py", pod_ip, timeout=75,
                         allow_failure=True)
    (lab.evidence / "llama-serving-client.raw.log").write_text(result.stdout + result.stderr)
    try:
        observed = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        lab.block(f"The llama client did not produce a valid receipt: {error}")
    (lab.evidence / "llama-serving.raw.json").write_text(
        json.dumps({"provenance": provenance, "observation": observed}, indent=2) + "\n")
    lab.check("positive", "The b9519 /tokenize IDs agree with the completion prompt count",
              result.returncode == 0
              and observed.get("completion_prompt_tokens_evaluated") in (
                  observed.get("prompt_token_count_add_special_false"),
                  observed.get("prompt_token_count_add_special_true"))
              and observed.get("model_alias") == "stories15m-moe"
              and observed.get("prompt_token_ids_add_special_false") == [9038, 2501, 263, 931],
              {"prompt_counts": [observed.get("prompt_token_count_add_special_false"),
                                  observed.get("prompt_token_count_add_special_true")],
               "completion_prompt_tokens_evaluated": observed.get(
                   "completion_prompt_tokens_evaluated"),
               "model_alias": observed.get("model_alias"),
               "tokenizer_endpoint": "/tokenize", "llama_release": "b9519"})
    lab.check("positive", "The actual CPU model emits exactly four bounded token IDs",
              result.returncode == 0
              and observed.get("completion_tokens") == 4
              and observed.get("completion_limit") == 4
              and observed.get("completion_stop_type") == "limit"
              and len(observed.get("completion_token_ids", [])) == 4,
              {"completion_tokens": observed.get("completion_tokens"),
               "limit": observed.get("completion_limit"),
               "stop_type": observed.get("completion_stop_type"),
               "model": "stories15m-moe", "gpu_layers": 0})
