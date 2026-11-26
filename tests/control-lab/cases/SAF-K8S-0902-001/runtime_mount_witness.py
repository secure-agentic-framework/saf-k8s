"""Scratch additive witness for an actual CPU model server under SAF-0902-001 posture."""
import json
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-0902-001"
POD = "pinned-llama-readonly-model"
CLIENT = "verify"
MODEL_PATH = "/artifact/stories15M_MOE-F16.gguf"
MODEL_SHA256 = "1240dfc1957df9f3550dd6c1d9e64b466fc2f452d8bc34bd4e45e1a1e2ca6055"
MODEL_BYTES = 73466432
PORT = 8080
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
PROBE_SHA256 = "f37b0988c36b55d10c104033a1de01ba677e4d456abfc63ce5a78060d6e183cc"


def _container_security():
    return {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]}}


def _runtime_pod(image):
    labels = {"saf-lab.example/control": "SAF-K8S-0902-001",
              "saf-lab.example/fixture": "pinned-cpu-serving"}
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": POD, "namespace": NAMESPACE, "labels": labels},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "runAsGroup": 65534, "fsGroup": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "initContainers": [{
                "name": "stage-approved-model", "image": image,
                "imagePullPolicy": "Never",
                "command": ["/bin/sh", "-c"],
                "args": ["set -eu; cp /models/stories15M_MOE-F16.gguf "
                         "/artifact/stories15M_MOE-F16.gguf; "
                         "chmod 0444 /artifact/stories15M_MOE-F16.gguf"],
                "volumeMounts": [{"name": "artifact", "mountPath": "/artifact",
                                  "readOnly": False}],
                "resources": {"requests": {"cpu": "20m", "memory": "64Mi",
                                             "ephemeral-storage": "96Mi"},
                              "limits": {"cpu": "200m", "memory": "192Mi",
                                         "ephemeral-storage": "128Mi"}},
                "securityContext": {**_container_security(), "runAsNonRoot": True,
                                    "runAsUser": 65534, "runAsGroup": 65534},
            }],
            "containers": [{
                "name": "llama-server", "image": image, "imagePullPolicy": "Never",
                "args": ["--model", MODEL_PATH, "--alias", "stories15m-moe",
                         "--host", "0.0.0.0", "--port", str(PORT), "--ctx-size", "256",
                         "--n-predict", "4", "--seed", "42", "--temp", "0",
                         "--threads", "1", "--parallel", "1", "--n-gpu-layers", "0"],
                "ports": [{"name": "http", "containerPort": PORT}],
                "startupProbe": {"httpGet": {"path": "/health", "port": "http"},
                                 "periodSeconds": 2, "timeoutSeconds": 2,
                                 "failureThreshold": 90},
                "readinessProbe": {"httpGet": {"path": "/health", "port": "http"},
                                   "periodSeconds": 2, "timeoutSeconds": 2,
                                   "failureThreshold": 3},
                "volumeMounts": [{"name": "artifact", "mountPath": "/artifact",
                                  "readOnly": True}],
                "resources": {"requests": {"cpu": "250m", "memory": "384Mi",
                                             "ephemeral-storage": "16Mi"},
                              "limits": {"cpu": "1500m", "memory": "768Mi",
                                         "ephemeral-storage": "64Mi"}},
                "securityContext": _container_security(),
            }, {
                "name": CLIENT, "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "-c", "import time; time.sleep(180)"],
                "volumeMounts": [{"name": "artifact", "mountPath": "/artifact",
                                  "readOnly": True}],
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "200m", "memory": "128Mi"}},
                "securityContext": {**_container_security(), "runAsNonRoot": True,
                                    "runAsUser": 65534, "runAsGroup": 65534},
            }],
            "volumes": [{"name": "artifact", "emptyDir": {"sizeLimit": "96Mi"}}],
        },
    }


def create_fixture(lab, resource):
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(resource))


def run_readonly_model_witness(lab, image, image_provenance=None, companion_sha256=None):
    """Pass the already built/loaded architecture-specific 0903-004 server image."""
    probe_code = (HERE / "probe.py").read_text(encoding="utf-8")
    probe_sha256 = hashlib.sha256(probe_code.encode("utf-8")).hexdigest()
    if probe_sha256 != PROBE_SHA256:
        lab.block("Read-only model verifier did not match its reviewed companion SHA-256")
    create_fixture(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": POD + "-probe", "namespace": NAMESPACE},
                "immutable": True,
                "data": {"probe.py": probe_code}})
    probe_cm = json.loads(lab.kubectl("-n", NAMESPACE, "get", "configmap",
                                      POD + "-probe", "-o", "json").stdout)
    stored_probe = probe_cm.get("data", {}).get("probe.py", "")
    stored_probe_sha256 = hashlib.sha256(stored_probe.encode("utf-8")).hexdigest()
    if probe_cm.get("immutable") is not True or stored_probe_sha256 != PROBE_SHA256:
        lab.block("The mounted probe ConfigMap is not immutable or differs from its reviewed SHA-256")
    pod = _runtime_pod(image)
    pod["spec"]["containers"][1]["volumeMounts"].append(
        {"name": "probe", "mountPath": "/fixture", "readOnly": True})
    pod["spec"]["volumes"].append(
        {"name": "probe", "configMap": {"name": POD + "-probe"}})
    create_fixture(lab, pod)
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", "pod/" + POD,
                "--timeout=150s", timeout=160)
    live = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pod", POD, "-o", "json").stdout)
    (lab.evidence / "actual-model-mount.pod.raw.json").write_text(
        json.dumps(live, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    spec = live["spec"]
    statuses = {row["name"]: row for row in live["status"]["containerStatuses"]}
    server_spec = next(row for row in spec["containers"] if row["name"] == "llama-server")
    server_security = server_spec.get("securityContext", {})
    if (spec.get("automountServiceAccountToken") is not False
            or spec.get("securityContext", {}).get("runAsNonRoot") is not True
            or server_spec.get("securityContext", {}).get("readOnlyRootFilesystem") is not True
            or not any(m.get("name") == "artifact" and m.get("readOnly") is True
                       for m in server_spec.get("volumeMounts", []))
            or not statuses["llama-server"].get("imageID")):
        lab.block("Actual model server Pod did not retain the reviewed nonroot/read-only configuration")
    init_spec = spec["initContainers"][0]
    init_status = live.get("status", {}).get("initContainerStatuses", [{}])[0]
    verifier_spec = next(row for row in spec["containers"] if row["name"] == CLIENT)
    artifact_volume = next(row for row in spec.get("volumes", [])
                          if row.get("name") == "artifact")
    if (init_spec.get("securityContext", {}).get("runAsNonRoot") is not True
            or init_spec.get("securityContext", {}).get("runAsUser") != 65534
            or init_spec.get("securityContext", {}).get("runAsGroup") != 65534
            or spec.get("securityContext", {}).get("fsGroup") != 65534
            or init_status.get("state", {}).get("terminated", {}).get("exitCode") != 0
            or not init_status.get("imageID")
            or statuses[CLIENT].get("ready") is not True
            or statuses[CLIENT].get("state", {}).get("running") is None
            or not statuses[CLIENT].get("imageID")
            or verifier_spec.get("securityContext", {}).get("runAsUser") != 65534):
        lab.block("The nonroot init copy or Pod-local verifier did not complete with the expected status")
    mount_result = lab.kubectl("-n", NAMESPACE, "exec", "pod/" + POD,
                               "-c", "llama-server", "--", "cat", "/proc/self/mountinfo",
                               timeout=20, allow_failure=True)
    (lab.evidence / "actual-server.mountinfo.raw.txt").write_text(
        mount_result.stdout + mount_result.stderr, encoding="utf-8")
    if mount_result.returncode != 0:
        lab.block("Could not read actual llama-server mountinfo")
    def mount_options(mountpoint):
        for line in mount_result.stdout.splitlines():
            left, separator, _right = line.partition(" - ")
            fields = left.split()
            if separator and len(fields) > 5 and fields[4] == mountpoint:
                return set(fields[5].split(","))
        return set()

    root_mount_ro = "ro" in mount_options("/")
    artifact_mount_ro = "ro" in mount_options("/artifact")
    token_probe = lab.kubectl("-n", NAMESPACE, "exec", "pod/" + POD,
                              "-c", "llama-server", "--", "/bin/sh", "-c",
                              "test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token",
                              timeout=20, allow_failure=True)
    token_path_absent = token_probe.returncode == 0
    (lab.evidence / "actual-server-token-path.raw.json").write_text(
        json.dumps({"server_token_path_probe_exit_code": token_probe.returncode,
                    "tokenless_pod_spec": spec.get("automountServiceAccountToken") is False,
                    "projected_service_account_volume_present": any(
                        "serviceAccountToken" in (volume.get("projected") or {})
                        for volume in spec.get("volumes", []))}, sort_keys=True, indent=2) + "\n",
        encoding="utf-8")
    result = lab.kubectl("-n", NAMESPACE, "exec", "pod/" + POD, "-c", CLIENT,
                         "--", "python", "-B", "/fixture/probe.py", timeout=90,
                         allow_failure=True)
    (lab.evidence / "actual-model-mount.raw.log").write_text(result.stdout + result.stderr,
                                                             encoding="utf-8")
    try:
        observation = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        lab.block(f"Actual server/mount verifier did not return bounded JSON: {error}")
    receipt = {"pod_uid": live["metadata"]["uid"], "server_image_id": statuses["llama-server"]["imageID"],
               "client_image_id": statuses[CLIENT]["imageID"], "model_sha256_expected": MODEL_SHA256,
               "model_bytes_expected": MODEL_BYTES, "probe_sha256": probe_sha256,
               "probe_configmap_uid": probe_cm["metadata"]["uid"],
               "init_image_id": init_status["imageID"], "init_exit_code": 0,
               "image_provenance": image_provenance,
               "companion_sha256": companion_sha256,
               "server_root_mount_read_only": root_mount_ro,
               "server_artifact_mount_read_only": artifact_mount_ro,
               "server_token_path_absent": token_path_absent,
               "gpu_layers": 0, "observation": observation,
               "scope": "one pinned CPU llama.cpp instance with an ordinary read-only model mount"}
    (lab.evidence / "actual-model-mount.raw.json").write_text(
        json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    lab.check("positive", "Pinned actual CPU server loads the approved model from a read-only mounted artifact",
              result.returncode == 0 and artifact_mount_ro
              and observation.get("mount_read_only") is True
              and observation.get("model_sha256") == MODEL_SHA256
              and observation.get("model_bytes") == MODEL_BYTES
              and observation.get("model_uid") == 65534
              and observation.get("model_gid") == 65534
              and observation.get("model_mode") == "0444"
              and observation.get("health_status") == 200
              and observation.get("model_alias") == "stories15m-moe",
              {"server_artifact_mount_read_only": artifact_mount_ro,
               "verifier_mount_read_only": observation.get("mount_read_only") is True,
               "model_sha256_matches_pin": observation.get("model_sha256") == MODEL_SHA256,
               "model_bytes_match_pin": observation.get("model_bytes") == MODEL_BYTES,
               "model_owner_is_init_uid": observation.get("model_uid") == 65534,
               "model_group_matches_fs_group": observation.get("model_gid") == 65534,
               "mode_is_read_only": observation.get("model_mode") == "0444",
               "server_healthy": observation.get("health_status") == 200,
               "model_alias_matches": observation.get("model_alias") == "stories15m-moe"})
    lab.check("positive", "Actual server has the reviewed tokenless nonroot read-only root posture",
              token_path_absent and root_mount_ro
              and spec.get("automountServiceAccountToken") is False
              and not any("serviceAccountToken" in (volume.get("projected") or {})
                          for volume in spec.get("volumes", []))
              and spec.get("securityContext", {}).get("fsGroup") == 65534
              and artifact_volume.get("emptyDir", {}).get("sizeLimit") == "96Mi"
              and spec.get("securityContext", {}).get("runAsNonRoot") is True
              and spec.get("securityContext", {}).get("runAsUser") == 65534
              and spec.get("securityContext", {}).get("seccompProfile", {}).get("type") == "RuntimeDefault"
              and init_spec.get("securityContext", {}).get("runAsNonRoot") is True
              and init_spec.get("securityContext", {}).get("runAsUser") == 65534
              and init_spec.get("securityContext", {}).get("runAsGroup") == 65534
              and init_status.get("state", {}).get("terminated", {}).get("exitCode") == 0
              and statuses[CLIENT].get("ready") is True
              and statuses[CLIENT].get("state", {}).get("running") is not None
              and server_security.get("allowPrivilegeEscalation") is False
              and server_security.get("readOnlyRootFilesystem") is True
              and "ALL" in server_security.get("capabilities", {}).get("drop", [])
              and statuses["llama-server"].get("ready") is True,
              {"service_account_token_path_absent": token_path_absent,
               "pod_token_automount_disabled": spec.get("automountServiceAccountToken") is False,
               "no_projected_service_account_token": not any(
                   "serviceAccountToken" in (volume.get("projected") or {})
                   for volume in spec.get("volumes", [])),
               "pod_run_as_nonroot": spec.get("securityContext", {}).get("runAsNonRoot") is True,
               "uid_is_unprivileged": spec.get("securityContext", {}).get("runAsUser") == 65534,
               "pod_fs_group_matches_init": spec.get("securityContext", {}).get("fsGroup") == 65534,
               "artifact_emptydir_is_bounded":
                   artifact_volume.get("emptyDir", {}).get("sizeLimit") == "96Mi",
               "init_runs_nonroot": init_spec.get("securityContext", {}).get("runAsNonRoot") is True,
               "init_uid_is_nonroot": init_spec.get("securityContext", {}).get("runAsUser") == 65534,
               "init_completed_successfully":
                   init_status.get("state", {}).get("terminated", {}).get("exitCode") == 0,
               "pod_local_verifier_ready": statuses[CLIENT].get("ready") is True,
               "runtime_default_seccomp":
                   spec.get("securityContext", {}).get("seccompProfile", {}).get("type") == "RuntimeDefault",
               "privilege_escalation_disabled": server_security.get("allowPrivilegeEscalation") is False,
               "all_capabilities_dropped": "ALL" in server_security.get("capabilities", {}).get("drop", []),
               "server_root_mount_read_only": root_mount_ro,
               "server_read_only_rootfs_spec": server_security.get("readOnlyRootFilesystem") is True,
               "server_container_ready": statuses["llama-server"].get("ready") is True})
    lab.check("positive", "Pinned server performs bounded native CPU generation with the mounted model",
              result.returncode == 0 and observation.get("prompt_token_ids") == [9038, 2501, 263, 931]
              and observation.get("completion_tokens") == 4
              and observation.get("completion_limit") == 4
              and observation.get("completion_stop_type") == "limit",
              {"prompt_token_ids_match_pin":
                   observation.get("prompt_token_ids") == [9038, 2501, 263, 931],
               "exact_four_tokens_generated": observation.get("completion_tokens") == 4,
               "four_token_limit": observation.get("completion_limit") == 4,
               "stopped_at_limit": observation.get("completion_stop_type") == "limit"})
