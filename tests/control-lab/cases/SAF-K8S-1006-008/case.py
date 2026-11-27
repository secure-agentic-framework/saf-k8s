"""Check synthetic AI development evidence links in isolated native Jobs."""
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NS = "saf-test"
SCOPE = (
    "One disposable Kubernetes v1.36.1 Kind cluster runs three native, short-lived Jobs using a "
    "digest-pinned Python image. Each Job reads only checked-in synthetic metadata: an inert "
    "dataset string, a training-run record marked not performed, and a metadata-only model "
    "artifact placeholder. The Jobs check schema/task identifiers, fixture digests, scope labels, "
    "and release-to-run artifact references. Separate Job status and logs expose a consistent "
    "development fixture, a deliberate release provenance mismatch, and an out-of-profile "
    "operation record whose governance and actual operation remain unknown. This does not train "
    "or load a model, establish organizational compliance, evaluate real data or weights, prove "
    "production provenance, or assess deployment/operation controls. Separate local Jobs "
    "gate a synthetic feature on the exact manifest and partition bytes, and a read-only "
    "Job checks the expected output or its absence."
    " Two case-owned namespaces compare bounded Kubernetes API authorization with short-lived projected "
    "ServiceAccount identities. A temporary cross-namespace binding establishes successful GET and LIST; "
    "its removal denies those requests for the developer while own reads and approved protected reads remain allowed. "
    "The readbacks follow the same immutable objects and the exact Job-owned Pods. Adopter evidence covers the broader PO.5.1 practice. "
    "Three additional bounded Jobs validate one synthetic Profile-applicability assessment record and two malformed counterfactuals; they verify record structure and reference integrity only."
)


def _security():
    return {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
        "runAsNonRoot": True,
        "runAsUser": 65534,
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def _job(name, scenario):
    config_name = name + "-fixture"
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": name, "labels": {"saf.synthetic": "true"}},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 60,
            "ttlSecondsAfterFinished": 600,
            "template": {
                "metadata": {"labels": {"saf.synthetic": "true", "saf.case": "1006-008"}},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 65534,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [{
                        "name": "evidence-checker",
                        "image": PYTHON_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "/fixture/validator.py", "/fixture/fixtures.json", scenario],
                        "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
                        "resources": {
                            "requests": {"cpu": "5m", "memory": "16Mi"},
                            "limits": {"cpu": "100m", "memory": "64Mi"},
                        },
                        "securityContext": _security(),
                        "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
                    }],
                    "volumes": [{"name": "fixture", "configMap": {
                        "name": config_name, "defaultMode": 292,
                    }}],
                },
            },
        },
    }


def _wait_job(lab, name):
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        conditions = {item.get("type"): item.get("status")
                      for item in job.get("status", {}).get("conditions", [])}
        if conditions.get("Complete") == "True":
            return "complete", job
        if conditions.get("Failed") == "True":
            return "failed", job
        time.sleep(0.5)
    lab.block(f"Native evidence Job {name} did not complete within 75 seconds")


def _run_scenario(lab, fixtures, scenario):
    name = f"saf-1006-008-{scenario}"
    config_name = name + "-fixture"
    fixture_bundle = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": config_name, "labels": {"saf.synthetic": "true"}},
        "immutable": True,
        "data": {
            "fixtures.json": json.dumps(fixtures, sort_keys=True),
            "validator.py": (HERE / "validator.py").read_text(encoding="utf-8"),
        },
    }
    lab.create(fixture_bundle)
    lab.create(_job(name, scenario))
    state, job = _wait_job(lab, name)
    pods = json.loads(lab.kubectl("get", "pods", "-l", "job-name=" + name, "-o", "json").stdout)
    pod_names = [item["metadata"]["name"] for item in pods.get("items", [])]
    if len(pod_names) != 1:
        lab.block(f"Expected one raw evidence Pod for {name}; found {len(pod_names)}")
    logs = lab.kubectl("logs", pod_names[0])
    pod = pods["items"][0]
    container, = pod["status"]["containerStatuses"]
    exit_code = container["state"]["terminated"]["exitCode"]
    observation = {
        "scenario": scenario,
        "job_state": state,
        "exit_code": exit_code,
        "raw_job": job,
        "raw_pods": pods,
        "raw_pod_logs": logs.stdout + logs.stderr,
        "fixture": fixtures["scenarios"][scenario],
    }
    (lab.evidence / f"{scenario}-raw-evidence.json").write_text(
        json.dumps(observation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return observation


def run(lab):
    server = json.loads(lab.kubectl("get", "--raw=/version").stdout).get("gitVersion")
    lab.check("positive", "Disposable API server is Kubernetes v1.36.1",
              server == "v1.36.1", {"server": server})

    fixtures = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
    consistent = _run_scenario(lab, fixtures, "consistent-development")
    good_logs = consistent["raw_pod_logs"]
    lab.check(
        "green",
        "Native Job validates versioned synthetic development evidence and matching release references",
        consistent["job_state"] == "complete" and consistent["exit_code"] == 0
        and '"decision": "fixture_consistent"' in good_logs
        and '"organizational_governance": "unknown"' in good_logs
        and '"actual_operation": "unknown"' in good_logs
        and '"environment_protection": "unknown"' in good_logs
        and '"training_executed": false' in good_logs
        and '"model_bytes_present": false' in good_logs
        and '"asserts_compliance": false' in good_logs,
        {"job_state": consistent["job_state"], "raw_pod_logs": good_logs},
    )

    mismatch = _run_scenario(lab, fixtures, "release-mismatch")
    mismatch_logs = mismatch["raw_pod_logs"]
    lab.check(
        "red",
        "Native Job rejects a release whose artifact version and digest do not match its training-run provenance",
        mismatch["job_state"] == "failed" and mismatch["exit_code"] == 23
        and "REJECT release_provenance_mismatch" in mismatch_logs,
        {"job_state": mismatch["job_state"], "raw_pod_logs": mismatch_logs},
    )

    scope = _run_scenario(lab, fixtures, "operation-scope-boundary")
    scope_logs = scope["raw_pod_logs"]
    lab.check(
        "positive",
        "Native Job marks AI system operation outside this Profile and preserves unknown governance and operation",
        scope["job_state"] == "complete" and scope["exit_code"] == 0
        and '"decision": "out_of_profile"' in scope_logs
        and '"organizational_governance": "unknown"' in scope_logs
        and '"actual_operation": "unknown"' in scope_logs
        and '"asserts_compliance": false' in scope_logs,
        {"job_state": scope["job_state"], "raw_pod_logs": scope_logs},
    )

    unknown = _run_scenario(lab, fixtures, "unknown-data-provenance")
    decision = json.loads(unknown["raw_pod_logs"])
    lab.check("red", "Unknown dataset provenance stays documented and cannot validate release readiness",
              unknown["job_state"] == "failed" and unknown["exit_code"] == 23
              and decision == {"decision": "provenance_gap", "dataset_id": unknown["fixture"]["dataset"]["dataset_id"],
                               "provenance_state": "unknown", "gap": unknown["fixture"]["dataset"]["provenance_gap"],
                               "asserts_compliance": False}, decision)

    # Keep the original metadata checker and all four outcomes above unchanged;
    # run this separately callable PW.3.1 local extension afterward.
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("saf_1006_008_integrated", HERE / "integrated_case.py")
    integrated = module_from_spec(spec)
    spec.loader.exec_module(integrated)
    integrated.run_integrated(lab, PYTHON_IMAGE)

    spec = spec_from_file_location("saf_1006_008_po51", HERE / "po51_isolation.py")
    isolation = module_from_spec(spec)
    spec.loader.exec_module(isolation)
    isolation.run(lab)

    assessment = _run_scenario(lab, fixtures, "profile-assessment-valid")
    assessment_result = json.loads(assessment["raw_pod_logs"])
    lab.check(
        "positive",
        "Native validator accepts a synthetic applicability record with rationale, resolved references, and an owned dated gap",
        assessment["job_state"] == "complete" and assessment["exit_code"] == 0
        and assessment_result == {
            "decision": "synthetic_assessment_record_complete",
            "assessment_id": "saf-fixture-assessment-001",
            "profile": "NIST.SP.800-218A-2024-07",
            "task_count": 3,
            "applicable_task_count": 2,
            "not_applicable_task_count": 1,
            "tracked_gap_count": 1,
            "reference_integrity": "fixture_ids_resolved",
            "risk_decisions": "not_evaluated",
            "organizational_approval": "not_evaluated",
            "asserts_compliance": False,
        },
        {"job_state": assessment["job_state"], "raw_pod_logs": assessment["raw_pod_logs"]},
    )

    missing_rationale = _run_scenario(lab, fixtures, "profile-assessment-missing-rationale")
    lab.check(
        "red",
        "Native validator rejects a task applicability decision without a rationale",
        missing_rationale["job_state"] == "failed" and missing_rationale["exit_code"] == 23
        and "REJECT applicability_rationale_missing" in missing_rationale["raw_pod_logs"],
        {"job_state": missing_rationale["job_state"], "raw_pod_logs": missing_rationale["raw_pod_logs"]},
    )

    unmapped = _run_scenario(lab, fixtures, "profile-assessment-unmapped-task")
    lab.check(
        "red",
        "Native validator rejects an applicable task without a valid control mapping",
        unmapped["job_state"] == "failed" and unmapped["exit_code"] == 23
        and "REJECT applicable_task_unmapped" in unmapped["raw_pod_logs"],
        {"job_state": unmapped["job_state"], "raw_pod_logs": unmapped["raw_pod_logs"]},
    )
