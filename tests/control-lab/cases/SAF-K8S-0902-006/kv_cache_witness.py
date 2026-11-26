"""Observe process-local cache behavior on pinned llama.cpp b9519."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMPANION = HERE.parent / "SAF-K8S-0903-004"
COMPANION_PINS = {
    "llama_runtime.py": "eb5431938939d15363a21f7c6dbb8126def4b99ec790e92a2be2e0bd40b513d8",
    "Dockerfile.llama": "9e9d4d3a6db46fac9fafca6fdc2b3ed2b703c24c5c49c87f7556aecd71057650",
}

NAMESPACE = "saf-test"
PREFIX = "saf-0902-006-kv"
PORT = 8080
MODEL = "/models/stories15M_MOE-F16.gguf"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)


def _server_pod(name, image):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {"saf-lab.example/control": "SAF-K8S-0902-006",
                                "saf-lab.example/fixture": "pinned-llama-cache"}},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "runAsGroup": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "llama-server", "image": image,
                "imagePullPolicy": "Never",
                "args": ["--model", MODEL, "--alias", "stories15m-moe",
                         "--host", "0.0.0.0", "--port", str(PORT),
                         "--ctx-size", "256", "--n-predict", "1", "--seed", "42",
                         "--temp", "0", "--threads", "1", "--parallel", "1",
                         "--n-gpu-layers", "0", "--slots"],
                "ports": [{"name": "http", "containerPort": PORT, "protocol": "TCP"}],
                "startupProbe": {"httpGet": {"path": "/health", "port": "http"},
                                 "periodSeconds": 2, "timeoutSeconds": 2,
                                 "failureThreshold": 90},
                "readinessProbe": {"httpGet": {"path": "/health", "port": "http"},
                                   "periodSeconds": 2, "timeoutSeconds": 2,
                                   "failureThreshold": 3},
                "resources": {"requests": {"cpu": "200m", "memory": "256Mi",
                                             "ephemeral-storage": "16Mi"},
                              "limits": {"cpu": "1500m", "memory": "768Mi",
                                         "ephemeral-storage": "64Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
            }],
        },
    }


def _client_pod():
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": PREFIX + "-client", "namespace": NAMESPACE,
                     "labels": {"saf-lab.example/control": "SAF-K8S-0902-006",
                                "saf-lab.example/fixture": "pinned-llama-client"}},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "volumes": [{"name": "client", "configMap": {"name": PREFIX + "-client"}}],
            "containers": [{
                "name": "client", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "-c", "import time; time.sleep(180)"],
                "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                              "limits": {"cpu": "200m", "memory": "96Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "client", "mountPath": "/fixture",
                                  "readOnly": True}],
            }],
        },
    }


def run_kv_cache_witness(lab):
    """Compare prompt-cache reuse and the initial state of a fresh process."""
    for name, expected_digest in COMPANION_PINS.items():
        path = COMPANION / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected_digest:
            lab.block(f"Pinned SAF-K8S-0903-004 companion changed or is missing: {name}")
    module_spec = importlib.util.spec_from_file_location(
        "saf_k8s_0903_004_llama_runtime", COMPANION / "llama_runtime.py")
    companion = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(companion)
    image, image_provenance = companion._build_and_load(lab)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": PREFIX + "-client", "namespace": NAMESPACE},
                "immutable": True, "data": {"llama_cache_client.py":
                                              (HERE / "llama_cache_client.py").read_text(encoding="utf-8")}})
    lab.create(_client_pod())
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready",
                "pod/" + PREFIX + "-client", "--timeout=60s", timeout=70)

    names = [PREFIX + "-a", PREFIX + "-b"]
    provenance = []
    for name in names:
        lab.create(_server_pod(name, image))
        lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", "pod/" + name,
                    "--timeout=120s", timeout=130)
        server = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pod", name,
                                        "-o", "json").stdout)
        spec = server["spec"]
        status = server["status"]["containerStatuses"][0]
        if (not server["status"].get("podIP") or not status.get("imageID")
                or spec.get("automountServiceAccountToken") is not False
                or spec["containers"][0]["securityContext"].get("allowPrivilegeEscalation") is not False):
            lab.block("The pinned llama cache witness did not retain its reviewed Pod identity/spec")
        provenance.append({"pod": name, "uid": server["metadata"]["uid"],
                           "pod_ip": server["status"]["podIP"],
                           "image_id": status["imageID"], "gpu_layers": 0,
                           "service_account_token_mounted": False})

    if provenance[0]["uid"] == provenance[1]["uid"]:
        lab.block("The two cache observations did not use distinct server Pod UIDs")
    result = lab.kubectl("-n", NAMESPACE, "exec", "pod/" + PREFIX + "-client", "--",
                         "python", "-B", "/fixture/llama_cache_client.py",
                         provenance[0]["pod_ip"], provenance[1]["pod_ip"],
                         timeout=90, allow_failure=True)
    (lab.evidence / "llama-kv-cache.raw.log").write_text(result.stdout + result.stderr,
                                                         encoding="utf-8")
    try:
        observation = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        lab.block(f"The cache client did not return bounded JSON evidence: {error}")
    receipt = {"release": "llama.cpp b9519", "model_alias": "stories15m-moe",
               "prompt": "Once upon a time", "pod_provenance": provenance,
               "image_provenance": image_provenance, "companion_sha256": COMPANION_PINS,
               "observation": observation,
               "claim_boundary": "process-local prompt-cache reuse; distinct fresh instance starts without prior prompt cache; no tenant, GPU, memory-zeroing, or concurrent-request isolation claim"}
    (lab.evidence / "llama-kv-cache.raw.json").write_text(
        json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    lab.check("positive", "b9519 reports prompt tokens reused on a repeated request to one instance",
              result.returncode == 0 and observation.get("a_first_cache_n") == 0
              and type(observation.get("a_second_cache_n")) is int
              and observation["a_second_cache_n"] > 0,
              {"first_cache_n": observation.get("a_first_cache_n"),
               "second_cache_n": observation.get("a_second_cache_n"),
               "endpoint": "/completion timings.cache_n"})
    lab.check("positive", "The same fixed request starts without reused prompt tokens on a fresh server instance",
              result.returncode == 0 and observation.get("b_first_cache_n") == 0
              and observation.get("a_second_cache_n", 0) > 0,
              {"a_cached_prompt_tokens": observation.get("a_second_cache_n"),
               "fresh_b_cached_prompt_tokens": observation.get("b_first_cache_n"),
               "distinct_pod_uids": provenance[0]["uid"] != provenance[1]["uid"]})
