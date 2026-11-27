"""Bounded actual-model smoke observation followed by a digest-bound hold."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
COMPANION = HERE.parent / "SAF-K8S-0903-004"
NAMESPACE = "saf-test"
SERVER = "saf-llama-real"
SERVER_LABEL = {"fixture": "saf-0905-045-native-model-server"}
EVALUATOR = "native-model-evaluator"
EVALUATOR_LABEL = {"app": EVALUATOR}
REVIEWER = "native-model-reviewer"
EVALUATION = "native-model-evaluation"
DISPOSITION = "native-model-disposition"
EVALUATOR_CODE = "native-model-evaluator-code"
REVIEWER_CODE = "native-model-reviewer-code"
RUNTIME_SOURCE_SHA256 = "eb5431938939d15363a21f7c6dbb8126def4b99ec790e92a2be2e0bd40b513d8"
DOCKERFILE_SHA256 = "9e9d4d3a6db46fac9fafca6fdc2b3ed2b703c24c5c49c87f7556aecd71057650"
MODEL_SHA256 = "1240dfc1957df9f3550dd6c1d9e64b466fc2f452d8bc34bd4e45e1a1e2ca6055"
MODEL_BYTES = 73466432
EXPECTED_PROMPT_IDS = [9038, 2501, 263, 931]


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _load_runtime(lab):
    runtime_path = COMPANION / "llama_runtime.py"
    dockerfile = COMPANION / "Dockerfile.llama"
    if _sha(runtime_path) != RUNTIME_SOURCE_SHA256 or _sha(dockerfile) != DOCKERFILE_SHA256:
        lab.block("The adjacent pinned llama.cpp companion source digest changed")
    spec = importlib.util.spec_from_file_location("saf_0903_004_llama_runtime", runtime_path)
    if spec is None or spec.loader is None:
        lab.block("Could not load the reviewed CPU serving companion")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _network_policies(lab):
    lab.create({
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "native-model-server-ingress"},
        "spec": {"podSelector": {"matchLabels": SERVER_LABEL},
                 "policyTypes": ["Ingress", "Egress"], "egress": [],
                 "ingress": [{"from": [{"podSelector": {"matchLabels": EVALUATOR_LABEL}}],
                              "ports": [{"protocol": "TCP", "port": 8080}]}]},
    })
    lab.create({
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "native-model-evaluator-egress"},
        "spec": {"podSelector": {"matchLabels": EVALUATOR_LABEL},
                 "policyTypes": ["Ingress", "Egress"], "ingress": [],
                 "egress": [{"to": [{"podSelector": {"matchLabels": SERVER_LABEL}}],
                             "ports": [{"protocol": "TCP", "port": 8080}]}]},
    })


def _reviewer_rbac(lab):
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": REVIEWER, "namespace": NAMESPACE}})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": REVIEWER, "namespace": NAMESPACE},
                "rules": [
                    {"apiGroups": [""], "resources": ["configmaps"],
                     "resourceNames": [EVALUATION], "verbs": ["get"]},
                    {"apiGroups": [""], "resources": ["configmaps"],
                     "resourceNames": [DISPOSITION], "verbs": ["get", "update"]},
                ]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": REVIEWER, "namespace": NAMESPACE},
                "subjects": [{"kind": "ServiceAccount", "name": REVIEWER,
                              "namespace": NAMESPACE}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": REVIEWER}})


def _evaluate(lab, python_image, make_job, wait_job, pod_security, auth):
    runtime_module = _load_runtime(lab)
    runtime_image, provenance = runtime_module._build_and_load(lab)
    server_spec = runtime_module._server_pod(runtime_image)
    server_spec["metadata"]["labels"] = SERVER_LABEL
    server_spec["metadata"]["name"] = SERVER
    evaluator_script = (HERE / "native_model_eval.py").read_text()
    reviewer_script = (HERE / "native_model_reviewer.py").read_text()
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": EVALUATOR_CODE}, "immutable": True,
                "data": {"native_model_eval.py": evaluator_script}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": REVIEWER_CODE}, "immutable": True,
                "data": {"native_model_reviewer.py": reviewer_script}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": DISPOSITION},
                "data": {"decision.json": "{}"}})
    _reviewer_rbac(lab)
    _network_policies(lab)
    lab.create(server_spec)
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + SERVER,
                "--timeout=195s", timeout=205)
    server = json.loads(lab.kubectl("get", "pod", SERVER, "-o", "json").stdout)
    statuses = server.get("status", {}).get("containerStatuses", [])
    conditions = {row.get("type") for row in server.get("status", {}).get("conditions", [])
                  if row.get("status") == "True"}
    if (server.get("metadata", {}).get("uid") is None or not server.get("status", {}).get("podIP")
            or len(statuses) != 1 or statuses[0].get("ready") is not True
            or re.fullmatch(r".+@sha256:[0-9a-f]{64}", statuses[0].get("imageID", "")) is None
            or "Ready" not in conditions
            or server.get("spec", {}).get("automountServiceAccountToken") is not False):
        lab.block("The pinned model server lacks a ready, tokenless runtime identity")
    server_uid = server["metadata"]["uid"]
    server_image_id = statuses[0]["imageID"]
    server_container = server.get("spec", {}).get("containers", [{}])[0]
    server_security = {
        "service_account_token_disabled":
            server.get("spec", {}).get("automountServiceAccountToken") is False,
        "run_as_non_root": server.get("spec", {}).get("securityContext", {}).get("runAsNonRoot"),
        "run_as_user": server.get("spec", {}).get("securityContext", {}).get("runAsUser"),
        "seccomp": server.get("spec", {}).get("securityContext", {}).get(
            "seccompProfile", {}).get("type"),
        "allow_privilege_escalation": server_container.get("securityContext", {}).get(
            "allowPrivilegeEscalation"),
        "read_only_root_filesystem": server_container.get("securityContext", {}).get(
            "readOnlyRootFilesystem"),
        "dropped_capabilities": server_container.get("securityContext", {}).get(
            "capabilities", {}).get("drop"),
    }
    server_args = server_container.get("args", [])
    def has_arg(name, value):
        return any(server_args[index + 1] == value
                   for index, arg in enumerate(server_args[:-1]) if arg == name)
    server_security["cpu_only_arguments"] = (
        has_arg("--n-gpu-layers", "0") and has_arg("--n-predict", "4"))
    provenance.update({"server_pod_uid": server_uid,
                       "runtime_image_id": server_image_id,
                       "server_pod_ip": server["status"]["podIP"],
                       "service_created": False,
                       "service_account_token_mounted": False})

    evaluator_job = make_job(EVALUATOR, python_image, "native_model_eval.py",
                             config_map=EVALUATOR_CODE, deadline=90)
    evaluator_container = evaluator_job["spec"]["template"]["spec"]["containers"][0]
    evaluator_container["env"] = [
        {"name": "MODEL_SERVER_IP", "value": server["status"]["podIP"]},
        {"name": "MODEL_SERVER_UID", "value": server_uid},
        {"name": "MODEL_SERVER_IMAGE_ID", "value": server_image_id},
        {"name": "MODEL_SHA256", "value": runtime_module.MODEL_SHA256},
        {"name": "MODEL_BYTES", "value": str(runtime_module.MODEL_BYTES if hasattr(runtime_module, "MODEL_BYTES") else MODEL_BYTES)},
        {"name": "LLAMA_RELEASE", "value": "b9519"},
    ]
    lab.create(evaluator_job)
    evaluator_job_result, runtime_receipt, evaluator_stdout = wait_job(lab, EVALUATOR)
    token_digest = runtime_receipt.get("request", {}).get("completion_token_ids_sha256")
    expected_runtime_fields = {
        "candidate_id": "external-stories15m-moe-fixture",
        "outcome": "inconclusive",
        "reason": "insufficient_evaluation_coverage",
        "model": {"alias": "stories15m-moe", "sha256": MODEL_SHA256,
                  "bytes": MODEL_BYTES, "llama_release": "b9519"},
        "runtime": {"pod_uid": server_uid, "image_id": server_image_id,
                    "health_status": 200},
        "request": {"prompt_sha256": hashlib.sha256(b"Once upon a time").hexdigest(),
                    "prompt_token_count": 4,
                    "prompt_token_ids_sha256": _digest(EXPECTED_PROMPT_IDS),
                    "completion_prompt_tokens_evaluated": 5,
                    "completion_token_count": 4,
                    "completion_token_ids_sha256": token_digest,
                    "completion_limit": 4, "completion_stop_type": "limit"},
        "coverage": "A fixed smoke request does not apply an approved model-safety rubric or representative evaluation set.",
    }
    receipt_without_digest = {key: value for key, value in runtime_receipt.items()
                              if key != "runtime_receipt_sha256"}
    expected_receipt = {**expected_runtime_fields,
                        "schema": "saf-lab/native-model-observation/v1"}
    if (not isinstance(token_digest, str) or re.fullmatch(r"[0-9a-f]{64}", token_digest) is None
            or runtime_receipt != {**expected_receipt,
                                   "runtime_receipt_sha256": _digest(expected_receipt)}
            or receipt_without_digest != expected_receipt):
        lab.block("The actual model observation did not match its fixed bounded schema")

    evaluation_digest = _digest(runtime_receipt)
    evaluation = runtime_receipt
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": EVALUATION}, "immutable": True,
                "data": {"evaluation.json": json.dumps(evaluation, sort_keys=True,
                                                        separators=(",", ":"))}})

    reviewer_job = make_job(REVIEWER, python_image, "native_model_reviewer.py",
                            service_account=REVIEWER, automount=True,
                            config_map=REVIEWER_CODE, deadline=60)
    lab.create(reviewer_job)
    reviewer_job_result, review_stdout, reviewer_logs = wait_job(lab, REVIEWER)
    disposition_obj = json.loads(lab.kubectl("get", "configmap", DISPOSITION, "-o", "json").stdout)
    disposition = json.loads(disposition_obj["data"]["decision.json"])
    reviewer_may_not_update_eval = not auth(
        lab, "update", "configmaps", "system:serviceaccount:saf-test:" + REVIEWER, EVALUATION)
    reviewer_security = pod_security(lab, REVIEWER)
    evaluator_security = pod_security(lab, EVALUATOR)
    normalized_runtime = {
        "model_digest_matches_pin": runtime_receipt.get("model", {}).get("sha256") == MODEL_SHA256,
        "model_runtime_identity_bound": runtime_receipt.get("runtime", {}).get("pod_uid") == server_uid
            and runtime_receipt.get("runtime", {}).get("image_id") == server_image_id,
        "fixed_prompt_was_tokenized": runtime_receipt.get("request", {}).get("prompt_token_count") == 4,
        "bounded_completion_observed": runtime_receipt.get("request", {}).get("completion_token_count") == 4
            and runtime_receipt.get("request", {}).get("completion_stop_type") == "limit",
        "server_pod_hardened": server_security == {
            "service_account_token_disabled": True, "run_as_non_root": True,
            "run_as_user": 65534, "seccomp": "RuntimeDefault",
            "allow_privilege_escalation": False, "read_only_root_filesystem": True,
            "dropped_capabilities": ["ALL"], "cpu_only_arguments": True,
        },
    }
    evaluator_hardened = (
        evaluator_security.get("service_account") == "default"
        and evaluator_security.get("automount_service_account_token") is False
        and evaluator_security.get("run_as_non_root") is True
        and evaluator_security.get("seccomp") == "RuntimeDefault"
        and evaluator_security.get("allow_privilege_escalation") is False
        and evaluator_security.get("read_only_root_filesystem") is True
        and evaluator_security.get("dropped_capabilities") == ["ALL"]
    )
    lab.check(
        "positive", "Pinned CPU model completes the fixed bounded request in its owned Pod",
        all(normalized_runtime.values())
        and evaluator_hardened,
        {**normalized_runtime,
         "evaluator_pod_hardened": evaluator_hardened,
         "model_alias": runtime_receipt["model"]["alias"],
         "completion_limit": runtime_receipt["request"]["completion_limit"]},
    )
    expected_disposition = {
        "candidate_id": "external-stories15m-moe-fixture",
        "disposition": "escalated",
        "reason": "insufficient_evaluation_coverage",
        "reviewer": REVIEWER,
        "evaluation_sha256": evaluation_digest,
        "runtime_receipt_sha256": runtime_receipt["runtime_receipt_sha256"],
    }
    review_ok = (
        review_stdout == expected_disposition
        and disposition == expected_disposition
        and reviewer_may_not_update_eval
        and reviewer_security.get("service_account") == REVIEWER
        and reviewer_security.get("automount_service_account_token") is True
        and bool(disposition_obj.get("metadata", {}).get("resourceVersion"))
    )
    raw = {
        "model_build_provenance": provenance,
        "server_pod": {"uid": server_uid, "image_id": server_image_id,
                       "ready": "Ready" in conditions,
                       "security": server_security},
        "evaluator_job_uid": evaluator_job_result.get("metadata", {}).get("uid"),
        "evaluator_stdout": evaluator_stdout,
        "evaluation": evaluation,
        "reviewer_job_uid": reviewer_job_result.get("metadata", {}).get("uid"),
        "reviewer_stdout": review_stdout,
        "disposition_readback": disposition,
        "disposition_resource_version": disposition_obj.get("metadata", {}).get("resourceVersion"),
        "evaluator_security": evaluator_security,
        "reviewer_security": reviewer_security,
        "reviewer_cannot_update_evaluation": reviewer_may_not_update_eval,
        "network_policy_specs_created": ["native-model-server-ingress",
                                          "native-model-evaluator-egress"],
        "network_policy_enforcement_verified": False,
    }
    (lab.evidence / "native-model-held.raw.json").write_text(
        json.dumps(raw, indent=2, sort_keys=True) + "\n")
    (lab.evidence / "native-model-held.normalized.json").write_text(json.dumps({
        "control_id": "SAF-K8S-0905-045",
        "runtime": normalized_runtime,
        "review": {"escalated": disposition.get("disposition") == "escalated",
                   "held": disposition.get("disposition") != "approved",
                   "runtime_digest_bound": disposition.get("runtime_receipt_sha256")
                       == runtime_receipt.get("runtime_receipt_sha256"),
                   "independent_readback_matches": disposition == expected_disposition},
        "limitations": {"actual_model_safety_pass": False,
                        "network_policy_enforcement_verified": False,
                        "generated_text_retained": False},
    }, indent=2, sort_keys=True) + "\n")
    lab.check(
        "green", "Independent reviewer durably escalates the exact real-model receipt and leaves it held",
        review_ok and disposition.get("disposition") == "escalated"
        and disposition.get("reason") == "insufficient_evaluation_coverage"
        and disposition.get("runtime_receipt_sha256") == runtime_receipt.get("runtime_receipt_sha256")
        and disposition.get("evaluation_sha256") == evaluation_digest,
        {"disposition": disposition.get("disposition"),
         "reason": disposition.get("reason"),
         "runtime_digest_bound": disposition.get("runtime_receipt_sha256")
             == runtime_receipt.get("runtime_receipt_sha256"),
         "independent_readback_matches": disposition == expected_disposition,
         "reviewer_cannot_update_evaluation": reviewer_may_not_update_eval},
    )


def run(lab, python_image, make_job, wait_job, pod_security, auth):
    _evaluate(lab, python_image, make_job, wait_job, pod_security, auth)
