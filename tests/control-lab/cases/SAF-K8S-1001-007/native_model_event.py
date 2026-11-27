"""Add a narrow native model-load and readiness event to SAF-K8S-1001-007."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import time


COMPANION = "SAF-K8S-0903-004"
COMPANION_SHA256 = {
    "llama_runtime.py": "eb5431938939d15363a21f7c6dbb8126def4b99ec790e92a2be2e0bd40b513d8",
    "Dockerfile.llama": "9e9d4d3a6db46fac9fafca6fdc2b3ed2b703c24c5c49c87f7556aecd71057650",
    "llama_client.py": "1a5da8194ad25415aaa7e3b8cc50ecc5d86257dedd7e115ad76db5f1f8d5986d",
}
MODEL_PATH = "/models/stories15M_MOE-F16.gguf"
MODEL_SHA256 = "1240dfc1957df9f3550dd6c1d9e64b466fc2f452d8bc34bd4e45e1a1e2ca6055"
NAMESPACE = "saf-test"
ISTIO_PROXY_IMAGE = (
    "docker.io/istio/proxyv2:1.32.0@sha256:"
    "b8d47c6d8d6e4b3fee7ae1e6f44339ec13091c24dc07f113a35efb0141a688d0"
)
MESH_SERVICE = "saf-llama-mesh"
MESH_CORRELATOR = "SAF1001-NATIVE-INFER-001"
MESH_CLIENT_PROGRAM = r'''import json,sys,urllib.request
host,correlator=sys.argv[1:3]
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
payload={"prompt":"Once upon a time","n_predict":4,"temperature":0.0,
         "seed":42,"ignore_eos":True,"return_tokens":True,"cache_prompt":False}
req=urllib.request.Request("http://"+host+":8080/completion",
    data=json.dumps(payload,separators=(",",":" )).encode(),
    headers={"Content-Type":"application/json","X-SAF-Case":correlator},method="POST")
with opener.open(req,timeout=25) as response:
    status=response.status
    raw=response.read(65536)
    if len(raw)>=65536: raise RuntimeError("bounded fixture response exceeded limit")
result=json.loads(raw)
count=result.get("tokens_predicted")
if status!=200 or count!=4 or result.get("stop_type")!="limit":
    raise RuntimeError("bounded fixture completion accounting differed")
print(json.dumps({"status":status,"tokens_predicted":count,
    "stop_type":result.get("stop_type"),"request_bytes":len(req.data),"response_bytes":len(raw),
    "correlation_id":correlator,"response_text_retained":False},sort_keys=True))
'''


def _load_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load reviewed companion file {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _verified_companion(case_dir: Path):
    directory = case_dir.parent / COMPANION
    for filename, expected in COMPANION_SHA256.items():
        path = directory / filename
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"hash-bound companion file mismatch: {filename}")
    return directory


def _kubectl(lab, *args, timeout=25, payload=None):
    """Use the owned Kind context without writing server/client output to commands.log."""
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
               f"kind-{lab.cluster}", "--namespace", NAMESPACE,
               f"--request-timeout={max(1, timeout - 5)}s", *args]
    return subprocess.run(command, input=payload, capture_output=True, text=True,
                          env=lab.env, timeout=timeout)


def _pod_json(lab):
    result = _kubectl(lab, "get", "pod", "saf-llama-real", "-o", "json")
    if result.returncode:
        lab.block("The owned native serving Pod could not be read")
    return json.loads(result.stdout)


def _named_pod_json(lab, name):
    result = _kubectl(lab, "get", "pod", name, "-o", "json")
    if result.returncode:
        lab.block(f"The owned Pod {name} could not be read")
    return json.loads(result.stdout)


def _digest_ref(value):
    value = value.removeprefix("docker-pullable://")
    digest = value.rsplit("@", 1)[-1] if "@" in value else ""
    return digest if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) else None


def _container_status(pod):
    return next((item for item in pod.get("status", {}).get("containerStatuses", [])
                 if item.get("name") == "llama-server"), {})


def _proxy_images(pod):
    # Istio 1.32 injects its proxy as a restartable init container (native
    # sidecar), so it is not necessarily in spec.containers.
    spec = pod.get("spec", {})
    containers = spec.get("containers", []) + spec.get("initContainers", [])
    return [item.get("image") for item in containers if item.get("name") == "istio-proxy"]


def _same_runtime_identity(before, after, expected_uid, expected_image_id):
    before_status = _container_status(before)
    after_status = _container_status(after)
    return (
        before.get("metadata", {}).get("uid") == expected_uid
        and after.get("metadata", {}).get("uid") == expected_uid
        and bool(before_status.get("containerID"))
        and before_status.get("containerID") == after_status.get("containerID")
        and before_status.get("imageID") == expected_image_id
        and after_status.get("imageID") == expected_image_id
    )


def _run_native_inference_mesh_correlation(
        lab, runtime, server_pod_uid, expected_image_id, expected_container_id):
    """Correlate one actual fixed model completion with metadata-only destination Envoy output."""
    service = json.loads(_kubectl(lab, "get", "service", MESH_SERVICE, "-o", "json").stdout)
    service_ip = service.get("spec", {}).get("clusterIP")
    if (service.get("spec", {}).get("selector") != {"fixture": runtime.SERVER}
            or len(service.get("spec", {}).get("ports", [])) != 1
            or service.get("spec", {}).get("ports", [{}])[0].get("port") != 8080
            or not service_ip or service_ip == "None"):
        lab.block("The model Service is not bound to the exact one-Pod fixture selector")
    endpoint_slices = []
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        response = _kubectl(lab, "get", "endpointslices",
            "-l", f"kubernetes.io/service-name={MESH_SERVICE}", "-o", "json")
        if response.returncode:
            lab.block("Could not read the case-owned model Service EndpointSlices")
        endpoint_slices = json.loads(response.stdout).get("items", [])
        all_ready = [ep for es in endpoint_slices for ep in es.get("endpoints", [])
            if ep.get("conditions", {}).get("ready") is True]
        exact = [ep for es in endpoint_slices for ep in es.get("endpoints", [])
            if ep.get("targetRef", {}).get("kind") == "Pod"
            and ep.get("targetRef", {}).get("uid") == server_pod_uid
            and ep.get("conditions", {}).get("ready") is True]
        # Bind the Service endpoint to the exact live model server Pod UID.
        if len(exact) == 1 and len(all_ready) == 1:
            break
        time.sleep(0.5)
    else:
        lab.block("The model Service did not resolve to exactly one Ready endpoint for the exact server Pod UID")
    client_pod = _named_pod_json(lab, runtime.CLIENT)
    client_uid = client_pod.get("metadata", {}).get("uid")
    proxy_images = _proxy_images(client_pod)
    server_pod = _pod_json(lab)
    server_proxy_images = _proxy_images(server_pod)
    if (not client_uid or proxy_images != [ISTIO_PROXY_IMAGE]
            or server_proxy_images != [ISTIO_PROXY_IMAGE]
            or _container_status(server_pod).get("imageID") != expected_image_id
            or _container_status(server_pod).get("containerID") != expected_container_id):
        lab.block("The mesh client/server or pinned native container identity did not match the fixture")
    execution = _kubectl(lab, "exec", "pod/" + runtime.CLIENT, "--", "python", "-B", "-c",
        MESH_CLIENT_PROGRAM, f"{MESH_SERVICE}.{NAMESPACE}.svc.cluster.local", MESH_CORRELATOR,
        timeout=45)
    try:
        client_record = json.loads(execution.stdout) if execution.returncode == 0 else {}
    except json.JSONDecodeError:
        client_record = {}
    # Completion can reach the client before Envoy's access log is readable.
    matching_lines = []
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        log_result = _kubectl(lab, "logs", "pod/" + runtime.SERVER, "-c", "istio-proxy",
                              "--since=2m", timeout=10)
        if log_result.returncode:
            lab.block("Could not inspect the bounded destination Envoy access log")
        matching_lines = [line for line in log_result.stdout.splitlines()
                          if line.startswith("SAF1001|") and MESH_CORRELATOR in line]
        if matching_lines:
            break
        time.sleep(0.3)
    fields = matching_lines[0].split("|") if len(matching_lines) == 1 else []
    try:
        received, sent = int(fields[4]), int(fields[5])
        byte_fields_valid = (received > 0 and sent > 0
                            and received == client_record.get("request_bytes")
                            and sent == client_record.get("response_bytes"))
    except (IndexError, ValueError):
        received = sent = 0
        byte_fields_valid = False
    log_match = (len(fields) == 7 and fields[0] == "SAF1001" and fields[1] == "POST"
        and fields[2] == "/completion" and fields[3] == "200"
        and fields[6] == MESH_CORRELATOR and byte_fields_valid)
    server_after = _pod_json(lab)
    same_native_identity = (server_after.get("metadata", {}).get("uid") == server_pod_uid
        and _container_status(server_after).get("imageID") == expected_image_id
        and _container_status(server_after).get("containerID") == expected_container_id)
    request_ok = (execution.returncode == 0 and client_record.get("status") == 200
        and client_record.get("tokens_predicted") == 4 and client_record.get("stop_type") == "limit"
        and client_record.get("correlation_id") == MESH_CORRELATOR
        and client_record.get("response_text_retained") is False)
    success = (request_ok and log_match and same_native_identity
        and len(exact) == 1 and proxy_images == [ISTIO_PROXY_IMAGE]
        and server_proxy_images == [ISTIO_PROXY_IMAGE])
    evidence = {"scope": "one fixed CPU model completion routed through one case-owned Istio Service, with metadata-only destination access log",
        "namespace": NAMESPACE, "service": {"name": MESH_SERVICE, "uid": service.get("metadata", {}).get("uid"),
            "selector": service.get("spec", {}).get("selector"), "cluster_ip": service_ip},
        "endpoint_slice_uids": [es.get("metadata", {}).get("uid") for es in endpoint_slices],
        "ready_endpoints_matching_exact_server_pod": len(exact),
        "ready_endpoint_count": len(all_ready),
        "server_pod_uid": server_pod_uid, "server_image_id": expected_image_id,
        "client_pod_uid": client_uid, "client_proxy_images": proxy_images,
        "server_proxy_images": server_proxy_images, "client_record": client_record,
        "correlator": MESH_CORRELATOR, "matching_destination_log_lines": matching_lines,
        "request_bytes": received, "response_bytes": sent,
        "native_server_uid_and_image_stable": same_native_identity,
        "request_metadata_matches": log_match, "request_completion_matches": request_ok,
        "prompt_or_completion_text_retained": False,
        "access_log_body_directives_enabled": False,
        "gpu_telemetry": False, "production_forwarding_or_retention": False}
    (lab.evidence / "native-inference-mesh-correlation.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lab.check("positive", "One actual bounded CPU model completion is correlated with its metadata-only destination Envoy record",
        success, {"native_completion_success_and_four_token_accounting": request_ok,
            "one_exact_ready_service_endpoint_uses_model_pod_uid": len(exact) == 1,
            "destination_envoy_record_matches_method_path_status_and_correlator": log_match,
            "pinned_mesh_proxies_and_native_model_identity_match": same_native_identity
                and proxy_images == [ISTIO_PROXY_IMAGE] and server_proxy_images == [ISTIO_PROXY_IMAGE],
            "prompt_or_response_text_retained": False})


def run_native_model_event(lab, case_dir: Path):
    """Run one fixed native CPU model request and minimize all captured evidence."""
    companion = _verified_companion(case_dir)
    runtime = _load_module(companion / "llama_runtime.py", "saf_0903_004_runtime_for_1001")
    image, provenance = runtime._build_and_load(lab)
    if provenance.get("model_sha256") != MODEL_SHA256:
        lab.block("The pinned serving companion did not produce the reviewed model digest")

    # b9519's legacy completion JSON exposes tokens_predicted from n_decoded.
    # Add that single native accounting value to the existing pinned client receipt.
    client_source = (companion / "llama_client.py").read_text(encoding="utf-8")
    needle = '    "completion_tokens": len(generated_ids),'
    if client_source.count(needle) != 1:
        lab.block("Pinned client no longer has the reviewed completion receipt insertion point")
    client_source = client_source.replace(
        needle, needle + '\n    "completion_accounted_tokens": completion.get("tokens_predicted"),', 1)
    executed_client_sha256 = hashlib.sha256(client_source.encode("utf-8")).hexdigest()
    configmap = {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": runtime.CLIENT_CONFIG, "namespace": NAMESPACE},
                 "immutable": True, "data": {"llama_client.py": client_source}}
    cm_result = _kubectl(lab, "create", "-f", "-", "-o", "json",
                         payload=json.dumps(configmap), timeout=20)
    if cm_result.returncode:
        lab.block("Could not create the bounded client fixture ConfigMap")
    # Istio is installed by the earlier mesh fixture. Label only this case
    # namespace before creating the two exact native test Pods.
    _kubectl(lab, "label", "namespace", NAMESPACE, "istio-injection=enabled", "--overwrite")
    server_pod = runtime._server_pod(image)
    server_pod.setdefault("metadata", {}).setdefault("annotations", {})[
        "sidecar.istio.io/proxyImage"] = ISTIO_PROXY_IMAGE
    model_args = server_pod["spec"]["containers"][0].get("args", [])
    if not ("--model" in model_args and model_args[model_args.index("--model") + 1] == MODEL_PATH):
        lab.block("The serving Pod does not use the pinned model path")
    lab.create(server_pod)
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + runtime.SERVER,
                "--timeout=190s", timeout=200)
    observed_server = _pod_json(lab)
    pod_uid = observed_server.get("metadata", {}).get("uid")
    pod_ip = observed_server.get("status", {}).get("podIP")
    container_statuses = observed_server.get("status", {}).get("containerStatuses", [])
    runtime_image_id = next((item.get("imageID") for item in container_statuses
                             if item.get("name") == "llama-server"), None)
    spec_container = next((item for item in observed_server.get("spec", {}).get("containers", [])
                           if item.get("name") == "llama-server"), {})
    if not pod_uid or not pod_ip or not runtime_image_id:
        lab.block("The owned serving Pod lacks UID, Pod IP, or runtime image identity")
    service = {"apiVersion": "v1", "kind": "Service",
        "metadata": {"name": MESH_SERVICE, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/control": "SAF-K8S-1001-007",
                                "saf-k8s.example/fixture": "native-inference-mesh"}},
        "spec": {"type": "ClusterIP", "ports": [{"name": "http", "port": 8080,
                    "protocol": "TCP", "targetPort": 8080}],
                 "selector": {"fixture": runtime.SERVER}}}
    service_result = _kubectl(lab, "create", "-f", "-", payload=json.dumps(service), timeout=20)
    if service_result.returncode:
        lab.block("Could not create the owned Service for the native inference correlation")
    initial_status = next((item for item in container_statuses if item.get("name") == "llama-server"), {})
    initial_container_id = initial_status.get("containerID")
    if not initial_container_id:
        lab.block("The owned serving Pod lacks its initial container runtime identity")

    # server.cpp emits "model loaded" only after load_model succeeds (b9519 L275-L286).
    # Retrieve a bounded log tail directly: Lab.command persists stdout in commands.log.
    log_result = _kubectl(lab, "logs", "pod/" + runtime.SERVER, "-c", "llama-server",
                          "--tail=350", timeout=15)
    if log_result.returncode:
        lab.block("Could not inspect bounded logs from the owned native server")
    model_loaded_count = sum(line.rstrip().endswith("model loaded")
                             for line in log_result.stdout.splitlines())

    # Verify the actual model bytes from inside the running server container.
    # The pinned official CPU image is Ubuntu-based; sha256sum is its coreutils
    # verifier. Capture directly so its output does not enter commands.log.
    model_hash_result = _kubectl(
        lab, "exec", "pod/" + runtime.SERVER, "-c", "llama-server", "--",
        "/usr/bin/sha256sum", MODEL_PATH, timeout=20)
    hash_match = re.fullmatch(r"([0-9a-f]{64})\s+(/models/stories15M_MOE-F16\.gguf)\s*",
                              model_hash_result.stdout) if model_hash_result.returncode == 0 else None
    observed_model_sha256 = hash_match.group(1) if hash_match else None
    model_path_from_hash = hash_match.group(2) if hash_match else None
    after_hash_server = _pod_json(lab)
    same_container_after_hash = _same_runtime_identity(
        observed_server, after_hash_server, pod_uid, runtime_image_id)

    client_pod = runtime._client_pod()
    client_pod.setdefault("metadata", {}).setdefault("annotations", {})[
        "sidecar.istio.io/proxyImage"] = ISTIO_PROXY_IMAGE
    lab.create(client_pod)
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + runtime.CLIENT,
                "--timeout=60s", timeout=70)
    result = _kubectl(lab, "exec", "pod/" + runtime.CLIENT, "--", "python", "-B",
                      "/fixture/llama_client.py", pod_ip, timeout=75)
    # The pinned client checks the fixed harmless prompt, /tokenize vector, health,
    # exact model alias and bounded completion. Its output omits generated text.
    try:
        client = json.loads(result.stdout) if result.returncode == 0 else {}
    except json.JSONDecodeError:
        client = {}
    final_server = _pod_json(lab)
    final_statuses = final_server.get("status", {}).get("containerStatuses", [])
    final_status = next((item for item in final_statuses if item.get("name") == "llama-server"), {})
    same_container_after_request = _same_runtime_identity(
        after_hash_server, final_server, pod_uid, runtime_image_id)
    same_container = (same_container_after_hash and same_container_after_request
                      and bool(initial_container_id)
                      and initial_container_id == final_status.get("containerID"))
    server_ready = (
        observed_server.get("status", {}).get("phase") == "Running"
        and any(condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in observed_server.get("status", {}).get("conditions", []))
        and client.get("health_status") == 200
        and client.get("model_alias") == "stories15m-moe"
    )
    fixed_request_completed = (
        result.returncode == 0
        and client.get("prompt_token_ids_add_special_false") == [9038, 2501, 263, 931]
        and client.get("completion_tokens") == 4
        and client.get("completion_accounted_tokens") == 4
        and client.get("completion_accounted_tokens") == client.get("completion_tokens")
        and client.get("completion_limit") == 4
        and client.get("completion_stop_type") == "limit"
        and len(client.get("completion_token_ids", [])) == 4
    )
    uid_bound = (pod_uid == observed_server.get("metadata", {}).get("uid")
                 and runtime_image_id
                 and spec_container.get("image") == image
                 and same_container)
    model_bound = (provenance.get("model_sha256") == MODEL_SHA256
                   and MODEL_PATH in spec_container.get("args", [])
                   and model_path_from_hash == MODEL_PATH
                   and observed_model_sha256 == MODEL_SHA256)
    node_name = f"{lab.cluster}-control-plane"
    cri_inspect = subprocess.run(
        ["docker", "exec", node_name, "crictl", "inspecti", image],
        capture_output=True, text=True, env=lab.env, timeout=15)
    cri_document = {}
    try:
        cri_document = json.loads(cri_inspect.stdout) if cri_inspect.returncode == 0 else {}
    except json.JSONDecodeError:
        pass
    cri_status = cri_document.get("status", {})
    cri_config_id = cri_status.get("id")
    cri_config_id_valid = bool(re.fullmatch(r"sha256:[0-9a-f]{64}", cri_config_id or ""))
    cri_config_id_matches = cri_config_id == provenance.get("derived_image_id")
    pod_manifest_digest = _digest_ref(runtime_image_id)
    cri_repo_digests = cri_status.get("repoDigests", [])
    matched_repo_digest = next((item for item in cri_repo_digests
                                if _digest_ref(item) == pod_manifest_digest), None)
    pod_digest_matches_cri_repo_digest = bool(pod_manifest_digest and matched_repo_digest)
    image_identity_join = cri_config_id_valid and pod_digest_matches_cri_repo_digest
    success = (model_loaded_count == 1 and server_ready and fixed_request_completed
               and image_identity_join
               and uid_bound and model_bound)

    # This local raw evidence contains no prompt or response text and no native log lines.
    # The stable receipt below contains booleans only.
    minimized = {
        "pod_name": runtime.SERVER,
        "pod_uid": pod_uid,
        "initial_pod_uid": observed_server.get("metadata", {}).get("uid"),
        "final_pod_uid": final_server.get("metadata", {}).get("uid"),
        "pod_ip_used_for_direct_client": pod_ip,
        "runtime_image_id_observed": runtime_image_id,
        "runtime_image_id_after_model_hash": _container_status(after_hash_server).get("imageID"),
        "runtime_image_id_after_request": final_status.get("imageID"),
        "runtime_container_id_before": initial_container_id,
        "runtime_container_id_after_model_hash": _container_status(after_hash_server).get("containerID"),
        "runtime_container_id_after": final_status.get("containerID"),
        "pod_uid_after_model_hash": after_hash_server.get("metadata", {}).get("uid"),
        "runtime_container_id_before_and_after_same": same_container,
        "derived_image_id": provenance.get("derived_image_id"),
        "pinned_image_reference": image,
        "cri_config_id": cri_status.get("id"),
        "cri_config_id_valid": cri_config_id_valid,
        "cri_config_id_matches_derived_image_id": cri_config_id_matches,
        "cross_runtime_config_id_agreement_observed": cri_config_id_matches,
        "docker_derived_config_id": provenance.get("derived_image_id"),
        "pod_manifest_digest": pod_manifest_digest,
        "matched_cri_repo_digest": matched_repo_digest,
        "pod_manifest_digest_matches_cri_repo_digest": pod_digest_matches_cri_repo_digest,
        "model_path": MODEL_PATH,
        "in_container_model_hash_path": model_path_from_hash,
        "in_container_model_sha256": observed_model_sha256,
        "in_container_model_sha256_matches_pin": observed_model_sha256 == MODEL_SHA256,
        "model_sha256": provenance.get("model_sha256"),
        "model_bytes": provenance.get("model_bytes"),
        "native_model_loaded_success_event_count": int(model_loaded_count),
        "native_model_loaded_event_exactly_once": model_loaded_count == 1,
        "ready_condition_and_native_http_health": server_ready,
        "client_source_sha256": COMPANION_SHA256["llama_client.py"],
        "executed_modified_client_sha256": executed_client_sha256,
        "fixed_client_result": {
            "returncode_zero": result.returncode == 0,
            "fixed_tokenizer_vector_matches": client.get("prompt_token_ids_add_special_false") == [9038, 2501, 263, 931],
            "model_alias_matches": client.get("model_alias") == "stories15m-moe",
            "completion_token_count": client.get("completion_tokens"),
            "native_tokens_predicted_accounting_count": client.get("completion_accounted_tokens"),
            "native_accounting_matches_returned_token_count": client.get("completion_accounted_tokens") == client.get("completion_tokens"),
            "completion_limit": client.get("completion_limit"),
            "completion_stopped_at_limit": client.get("completion_stop_type") == "limit",
            "generated_text_retained": False,
        },
        "server_spec_image_matches_loaded_reference": spec_container.get("image") == image,
        "service_created": True,
        "service_account_token_mounted": observed_server.get("spec", {}).get("automountServiceAccountToken") is not False,
        "gpu_layers": 0,
        "native_startup_log_lines_retained": False,
        "prompt_or_response_text_retained": False,
    }
    (lab.evidence / "native-model-load-event.json").write_text(
        json.dumps(minimized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lab.check(
        "positive",
        "The pinned CPU model reaches native loaded state and completes one fixed bounded request in the same owned Pod",
        success,
        {
            "native_model_loaded_success_event_exactly_once": model_loaded_count == 1,
            "model_digest_matches_pin": model_bound,
            "pod_uid_container_and_manifest_identity_bound": uid_bound and image_identity_join,
            "cri_config_id_is_valid": cri_config_id_valid,
            "in_container_model_bytes_match_pin": observed_model_sha256 == MODEL_SHA256
                and model_path_from_hash == MODEL_PATH,
            "ready_http_model_identity_observed": server_ready,
            "fixed_bounded_completion_observed": fixed_request_completed,
            "native_completion_accounting_equals_four": client.get("completion_accounted_tokens") == 4,
            "native_startup_output_not_retained": True,
            "prompt_or_response_text_not_retained": True,
        },
    )
    _run_native_inference_mesh_correlation(
        lab, runtime, pod_uid, runtime_image_id, initial_container_id)
