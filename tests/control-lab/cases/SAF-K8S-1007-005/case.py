"""Exercise a synthetic local change gate and API-observable Deployment rollback."""
from copy import deepcopy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import time

HERE = Path(__file__).resolve().parent
FIXTURE_PATH = HERE / "fixtures" / "change.json"
CONTROL_ID = "SAF-K8S-1007-005"
NAMESPACE = "saf-test"
DEPLOYMENT = "saf-1007-005-mock-inference"
LABEL_KEY = "saf-lab.example/control"
LABEL_VALUE = CONTROL_ID
PROBE = "saf-1007-005-service-observer"
SCOPE = (
    "One disposable Kind cluster and a case-owned, single-replica Python Deployment. A local gate "
    "requires an exact synthetic change fingerprint, explicit fixture approval, two approval roles, "
    "a fixed window, risk below a configured limit, and a pinned image. The actual Pod serves an "
    "inert linear model from an immutable fixture file whose SHA-256 it verifies before readiness. "
    "Independent Service reads compare fixed predictions before a rejected change, after the "
    "approved rollout, and after Kubernetes rollback. Real release trust, actual organizational "
    "approval, risk calibration, serving-model quality, and production rollout traffic require "
    "separate evidence."
)


def _parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _canonical_sha256(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _approved_change_fields(change):
    return {key: change[key] for key in (
        "change_id", "release", "model_digest", "risk_score", "fixture_image")}


def evaluate_gate(fixture, change, approval):
    """Return deterministic gate findings; this function performs no cluster operations."""
    policy = fixture["policy"]
    now = _parse_time(fixture["fixed_now"])
    window_start = _parse_time(policy["deployment_window_start"])
    window_end = _parse_time(policy["deployment_window_end"])
    approved_at = _parse_time(approval["approved_at"])
    roles = set(approval.get("approved_roles", []))
    required_roles = set(policy["required_approval_roles"])
    image = change.get("fixture_image", "")
    digest_format_ok = bool(re.fullmatch(r"docker\.io/library/python:[^@]+@sha256:[0-9a-f]{64}", image))
    findings = {
        "explicit_approval": approval.get("explicitly_approved") is True,
        "required_synthetic_roles": required_roles <= roles,
        "change_fingerprint_approved": (
            approval.get("approved_change_sha256") == _canonical_sha256(_approved_change_fields(change))
        ),
        "within_fixed_deployment_window": window_start <= now <= window_end,
        "approval_precedes_fixed_now": approved_at <= now,
        "risk_below_configured_limit": (
            type(change.get("risk_score")) is int
            and change["risk_score"] < policy["maximum_risk_score"]
        ),
        "mock_image_digest_pinned": digest_format_ok and image == fixture["mock_workload"]["image"],
        "synthetic_model_digest_well_formed": bool(
            re.fullmatch(r"sha256:[0-9a-f]{64}", change.get("model_digest", ""))
        ),
    }
    return {"accepted": all(findings.values()), "findings": findings}


def _artifact_config_name(model_digest):
    return f"{DEPLOYMENT}-model-{model_digest[7:19]}"


def _install_artifacts(lab, fixture):
    source = (HERE / "server.py").read_text()
    artifacts = (
        (fixture["mock_workload"]["baseline_model_digest"], "baseline-model.json"),
        (fixture["proposed_change"]["model_digest"], "candidate-model.json"),
    )
    for digest, name in artifacts:
        artifact = (HERE / "fixtures" / name).read_bytes()
        if digest != "sha256:" + hashlib.sha256(artifact).hexdigest():
            lab.block("The checked-in fixture model digest does not match the change record")
        lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": _artifact_config_name(digest), "namespace": NAMESPACE},
                    "immutable": True,
                    "data": {"model.json": artifact.decode(), "server.py": source}})
    lab.create({"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": DEPLOYMENT, "namespace": NAMESPACE},
                "spec": {"selector": {"app": DEPLOYMENT},
                         "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]}})

    lab.create({"apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": PROBE, "namespace": NAMESPACE},
                "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [{"name": "probe", "image": fixture["mock_workload"]["image"],
                                         "command": ["python", "-B", "-c", "import time; time.sleep(420)"],
                                         "securityContext": {"allowPrivilegeEscalation": False,
                                                             "readOnlyRootFilesystem": True,
                                                             "capabilities": {"drop": ["ALL"]}},
                                         "resources": {"requests": {"cpu": "5m", "memory": "16Mi"},
                                                       "limits": {"cpu": "75m", "memory": "64Mi"}}}]}})
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{PROBE}", "--timeout=65s", timeout=75)

def _independent_prediction(lab, release, digest, predictions):
    expected = {"model_digest": digest, "release": release, "inputs": [-1, 0, 3],
                "predictions": predictions}
    request = "from urllib.request import urlopen; import sys; print(urlopen(sys.argv[1], timeout=3).read(4096).decode())"
    target = f"http://{DEPLOYMENT}.{NAMESPACE}.svc.cluster.local:8080/predict"
    deadline = time.monotonic() + 25
    observed = None
    while time.monotonic() < deadline:
        response = lab.kubectl("exec", f"pod/{PROBE}", "--", "python", "-B", "-c", request, target,
                               allow_failure=True, timeout=10)
        if response.returncode == 0:
            observed = json.loads(response.stdout)
            if observed == expected:
                break
        time.sleep(0.5)
    return {"matched": observed == expected, "expected": expected, "observed": observed}


def _deployment(fixture, release, model_digest):
    image = fixture["mock_workload"]["image"]
    labels = {LABEL_KEY: LABEL_VALUE, "saf-lab.example/fixture": "synthetic"}
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": DEPLOYMENT, "namespace": NAMESPACE, "labels": labels,
                     "annotations": {"kubernetes.io/change-cause": f"fixture release {release}"}},
        "spec": {
            "replicas": 1,
            "revisionHistoryLimit": 4,
            "selector": {"matchLabels": {"app": DEPLOYMENT}},
            "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 1, "maxUnavailable": 0}},
            "template": {
                "metadata": {"labels": {"app": DEPLOYMENT, **labels}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "terminationGracePeriodSeconds": 3,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "artifact", "configMap": {"name": _artifact_config_name(model_digest)}}],
                    "containers": [{
                        "name": "mock-inference", "image": image,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "-B", "/fixture/server.py"],
                        "readinessProbe": {"httpGet": {"path": "/healthz", "port": 8080}, "periodSeconds": 1},
                        "volumeMounts": [{"name": "artifact", "mountPath": "/fixture", "readOnly": True}],
                        "env": [
                            {"name": "SAF_FIXTURE_RELEASE", "value": release},
                            {"name": "SAF_FIXTURE_MODEL_DIGEST", "value": model_digest},
                        ],
                        "securityContext": {"allowPrivilegeEscalation": False,
                                            "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                      "limits": {"cpu": "100m", "memory": "64Mi"}},
                    }],
                },
            },
        },
    }


def _apply(lab, resource):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(resource))


def submit_change(lab, fixture, change, approval):
    decision = evaluate_gate(fixture, change, approval)
    if decision["accepted"]:
        _apply(lab, _deployment(fixture, change["release"], change["model_digest"]))
    return decision


def _ready_pod_markers(lab):
    response = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pods", "-l", f"app={DEPLOYMENT}",
                                      "-o", "json").stdout)
    ready = [pod for pod in response["items"] if not pod["metadata"].get("deletionTimestamp")
             and any(item["type"] == "Ready" and item["status"] == "True"
                     for item in pod["status"].get("conditions", []))]
    if len(ready) != 1:
        lab.block("Expected one Ready Pod for the case-owned Deployment")
    pod = ready[0]["metadata"]["name"]
    code = """import json
from os import environ
print(json.dumps([environ['SAF_FIXTURE_RELEASE'], environ['SAF_FIXTURE_MODEL_DIGEST']]))
"""
    return json.loads(lab.kubectl("-n", NAMESPACE, "exec", f"pod/{pod}", "--",
                                   "python", "-c", code).stdout)


def _get_deployment(lab):
    return json.loads(lab.kubectl(
        "-n", NAMESPACE, "get", "deployment", DEPLOYMENT, "-o", "json").stdout)


def _view(resource):
    metadata = resource.get("metadata", {})
    spec = resource.get("spec", {})
    template = spec.get("template", {})
    pod_spec = template.get("spec", {})
    container = (pod_spec.get("containers") or [{}])[0]
    env = {entry["name"]: entry["value"] for entry in container.get("env", [])}
    status = resource.get("status", {})
    return {
        "uid": metadata.get("uid"),
        "generation": metadata.get("generation"),
        "observed_generation": status.get("observedGeneration"),
        "revision": metadata.get("annotations", {}).get("deployment.kubernetes.io/revision"),
        "change_cause": metadata.get("annotations", {}).get("kubernetes.io/change-cause"),
        "image": container.get("image"),
        "release": env.get("SAF_FIXTURE_RELEASE"),
        "model_digest": env.get("SAF_FIXTURE_MODEL_DIGEST"),
        "replicas": status.get("replicas", 0),
        "ready_replicas": status.get("readyReplicas", 0),
        "updated_replicas": status.get("updatedReplicas", 0),
        "available_replicas": status.get("availableReplicas", 0),
        "conditions": [{"type": c.get("type"), "status": c.get("status"),
                        "reason": c.get("reason")} for c in status.get("conditions", [])],
    }


def _save_raw(lab, name, value):
    (lab.evidence / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _rollout(lab):
    lab.kubectl("-n", NAMESPACE, "rollout", "status", f"deployment/{DEPLOYMENT}",
                "--timeout=150s", timeout=160)


def run(lab):
    fixture = json.loads(FIXTURE_PATH.read_text())
    baseline_cfg = fixture["mock_workload"]
    change = fixture["proposed_change"]
    approval = fixture["approval"]
    _install_artifacts(lab, fixture)

    baseline = _deployment(fixture, baseline_cfg["baseline_release"],
                           baseline_cfg["baseline_model_digest"])
    _apply(lab, baseline)
    _rollout(lab)
    baseline_live = _get_deployment(lab)
    baseline_view = _view(baseline_live)
    if not baseline_view["uid"] or baseline_view["ready_replicas"] != 1:
        lab.block("Case-owned mock Deployment did not become ready")
    baseline_markers = _ready_pod_markers(lab)
    if baseline_markers != [baseline_cfg["baseline_release"], baseline_cfg["baseline_model_digest"]]:
        lab.block("Live baseline Pod did not report the expected fixture markers")
    _save_raw(lab, "baseline-deployment.raw.json", baseline_live)
    expected_baseline = [-1, 1, 7]
    baseline_behavior = _independent_prediction(lab, *baseline_markers, expected_baseline)

    # An approval copied from the fixture cannot authorize a modified fingerprint.
    altered = deepcopy(change)
    altered["risk_score"] = fixture["policy"]["maximum_risk_score"] + 1
    rejected_approval = deepcopy(approval)
    rejected_approval["explicitly_approved"] = False
    rejected_gate = submit_change(lab, fixture, altered, rejected_approval)
    late_fixture = {**fixture, "fixed_now": "2026-11-22T14:00:00Z"}
    late = submit_change(lab, late_fixture, change, approval)
    unsigned_role = {**approval, "approved_roles": approval["approved_roles"][:-1]}
    missing_role = submit_change(lab, fixture, change, unsigned_role)
    late_only_denial = ([name for name, ok in late["findings"].items() if not ok]
                        == ["within_fixed_deployment_window"])
    role_only_denial = ([name for name, ok in missing_role["findings"].items() if not ok]
                        == ["required_synthetic_roles"])
    after_rejection = _get_deployment(lab)
    unchanged = _view(after_rejection) == baseline_view
    _save_raw(lab, "rejected-change.raw.json", {
        "request": altered, "gate": rejected_gate,
        "outside_window": late, "missing_approval_role": missing_role,
        "deployment_before": baseline_view, "deployment_after": _view(after_rejection),
    })
    lab.check("red", "Unapproved above-limit change is rejected before any Deployment mutation",
              not rejected_gate["accepted"] and not rejected_gate["findings"]["explicit_approval"]
              and not rejected_gate["findings"]["change_fingerprint_approved"]
              and not rejected_gate["findings"]["risk_below_configured_limit"] and unchanged
              and late_only_denial and role_only_denial and not late["accepted"] and not missing_role["accepted"],
              {"gate_rejected": not rejected_gate["accepted"],
               "approval_rejected": not rejected_gate["findings"]["explicit_approval"],
               "approved_fingerprint_did_not_match": not rejected_gate["findings"]["change_fingerprint_approved"],
               "risk_limit_enforced": not rejected_gate["findings"]["risk_below_configured_limit"],
               "api_state_unchanged": unchanged, "outside_window_rejected": late_only_denial,
               "missing_role_rejected": role_only_denial})

    denied_behavior = _independent_prediction(lab, *baseline_markers, expected_baseline)

    accepted_gate = submit_change(lab, fixture, change, approval)
    lab.check("green", "Fixture-approved change meets the fixed window, role, fingerprint, risk, and digest checks",
              accepted_gate["accepted"], accepted_gate)
    if not accepted_gate["accepted"]:
        lab.block("Approved fixture did not pass the local gate; refusing Kubernetes mutation")

    _rollout(lab)
    candidate_live = _get_deployment(lab)
    candidate_view = _view(candidate_live)
    candidate_replicas = json.loads(lab.kubectl(
        "-n", NAMESPACE, "get", "replicasets", "-l", f"app={DEPLOYMENT}", "-o", "json").stdout)
    candidate_revision = candidate_view["revision"]
    candidate_pod = _ready_pod_markers(lab)
    candidate_markers_match = candidate_pod == [change["release"], change["model_digest"]]
    candidate_ready = (
        candidate_view["release"] == change["release"]
        and candidate_view["model_digest"] == change["model_digest"]
        and candidate_view["image"] == baseline_cfg["image"]
        and candidate_view["ready_replicas"] == 1
        and candidate_view["updated_replicas"] == 1
        and candidate_view["available_replicas"] == 1
        and candidate_view["observed_generation"] == candidate_view["generation"]
        and candidate_revision != baseline_view["revision"] and candidate_markers_match
    )
    _save_raw(lab, "approved-rollout.raw.json", {
        "gate": accepted_gate, "deployment": candidate_live,
        "replicasets": candidate_replicas, "pod_markers": candidate_pod,
    })
    lab.check("positive", "Approved release is a ready API-observed Deployment revision",
              candidate_ready,
              {"release": candidate_view["release"], "model_digest": candidate_view["model_digest"],
               "digest_pinned_mock_image": "@sha256:" in candidate_view["image"],
               "ready_replicas": candidate_view["ready_replicas"],
               "live_pod_markers_match": candidate_markers_match,
               "revision_advanced": candidate_revision != baseline_view["revision"],
               "observed_generation_matches": candidate_view["observed_generation"] == candidate_view["generation"]})
    if not candidate_ready:
        lab.block("Approved fixture Deployment did not reach the expected API-observed rollout")

    candidate_behavior = _independent_prediction(lab, *candidate_pod, [-1, 2, 11])

    lab.kubectl("-n", NAMESPACE, "rollout", "undo", f"deployment/{DEPLOYMENT}",
                f"--to-revision={baseline_view['revision']}")
    _rollout(lab)
    rolled_back_live = _get_deployment(lab)
    rollback_view = _view(rolled_back_live)
    rollback_markers_match = _ready_pod_markers(lab) == baseline_markers
    restored = (
        rollback_view["release"] == baseline_cfg["baseline_release"]
        and rollback_view["model_digest"] == baseline_cfg["baseline_model_digest"]
        and rollback_view["image"] == baseline_cfg["image"]
        and rollback_view["ready_replicas"] == 1
        and rollback_view["observed_generation"] == rollback_view["generation"]
        and rollback_view["revision"] != candidate_revision and rollback_markers_match
    )
    _save_raw(lab, "rollback-deployment.raw.json", rolled_back_live)
    lab.check("green", "Rollback restores the prior synthetic release and a ready API-observed revision",
              restored,
              {"release_restored": rollback_view["release"] == baseline_cfg["baseline_release"],
               "live_pod_markers_restored": rollback_markers_match,
               "model_digest_restored": rollback_view["model_digest"] == baseline_cfg["baseline_model_digest"],
               "ready_replicas": rollback_view["ready_replicas"],
               "rollback_revision_observed": rollback_view["revision"] != candidate_revision,
               "observed_generation_matches": rollback_view["observed_generation"] == rollback_view["generation"]})

    restored_behavior = _independent_prediction(lab, *baseline_markers, expected_baseline)
    predictions = {"baseline": baseline_behavior, "after_refusal": denied_behavior,
                   "after_approved_rollout": candidate_behavior, "after_rollback": restored_behavior}
    _save_raw(lab, "served-model-predictions.json", predictions)
    matched = {name: outcome["matched"] for name, outcome in predictions.items()}
    lab.check("positive", "Independent Service predictions change on approved rollout and restore on model rollback",
              all(matched.values()), matched)
