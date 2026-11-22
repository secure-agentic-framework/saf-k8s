"""Exercise a synthetic post-incident artifact integrity gate in native Jobs."""
import hashlib
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-test"
CONFIG = "saf-1005-015-integrity-fixtures"
BASELINE_SHA256 = "8176b6cb32837a6710222858fc244c8a9368e6d577da489afb7e5b1edebb7fac"
SCOPE = (
    "One disposable Kind Kubernetes v1.36.1 cluster runs restricted, tokenless native Jobs. "
    "They process only one harmless synthetic plain-text fixture, synthetic approval metadata, and "
    "a pre-incident SHA-256 record stored in a Kubernetes immutable ConfigMap. A bypass comparator "
    "accepts a changed candidate; the enabled gate blocks it and accepts byte-identical approved "
    "reconstruction. This demonstrates a fixture-level byte-identity check and decision path only. "
    "It does not use, test, represent, or establish the safety of an AI model; prove approval identity, "
    "signature authenticity, or baseline protection from a cluster administrator; or establish "
    "production incident response, registry, signature, behavioral-validation, monitoring, or deployment coverage."
)


def _fixture_data():
    names = ("pre-incident.txt", "reconstructed.txt", "changed.txt",
             "integrity-record.json", "approval.json")
    files = {name: (FIXTURES / name).read_text(encoding="utf-8") for name in names}
    preincident_hash = hashlib.sha256((FIXTURES / "pre-incident.txt").read_bytes()).hexdigest()
    record = json.loads(files["integrity-record.json"])
    approval = json.loads(files["approval.json"])
    if (preincident_hash != BASELINE_SHA256 or record.get("sha256") != BASELINE_SHA256
            or approval.get("approved_sha256") != BASELINE_SHA256):
        raise ValueError("Synthetic pre-incident fixture digest and approval metadata do not agree")
    files["integrity_gate.py"] = (HERE / "integrity_gate.py").read_text(encoding="utf-8")
    return files


def _job(name, mode, candidate, config):
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "labels": {"saf-lab.example/control": "1005-015"}},
        "spec": {
            "backoffLimit": 0, "activeDeadlineSeconds": 75,
            "template": {
                "metadata": {"labels": {"saf-lab.example/job": name}},
                "spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True, "runAsUser": 65534,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [{
                        "name": "integrity-check", "image": PYTHON_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "env": [{"name": "EXPECTED_BASELINE", "value": BASELINE_SHA256}],
                        "command": ["python", "/fixture/integrity_gate.py", "--mode", mode,
                                    "--candidate", candidate],
                        "securityContext": {
                            "readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                      "limits": {"cpu": "100m", "memory": "64Mi"}},
                        "volumeMounts": [{"name": "fixtures", "mountPath": "/fixture",
                                          "readOnly": True}],
                    }],
                    "volumes": [{"name": "fixtures", "configMap": {"name": config}}],
                },
            },
        },
    }


def _observe_job(lab, name):
    deadline = time.monotonic() + 95
    job = None
    terminal = None
    while time.monotonic() < deadline:
        result = lab.kubectl("get", "job", name, "-o", "json", timeout=20)
        job = json.loads(result.stdout)
        conditions = job.get("status", {}).get("conditions", [])
        terminal = next((row["type"] for row in conditions
                         if row.get("status") == "True" and row.get("type") in {"Complete", "Failed"}), None)
        if terminal:
            break
        time.sleep(1)
    if not terminal:
        lab.block(f"Synthetic integrity Job {name} did not reach Complete or Failed")

    pods = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={name}", "-o", "json").stdout)["items"]
    if len(pods) != 1:
        lab.block(f"Expected exactly one case-owned Pod for Job {name}, observed {len(pods)}")
    pod = pods[0]
    statuses = pod.get("status", {}).get("containerStatuses", [])
    terminated = statuses[0].get("state", {}).get("terminated") if statuses else None
    if not terminated:
        lab.block(f"Synthetic integrity Job {name} has no terminated container outcome")
    logs = lab.kubectl("logs", f"job/{name}").stdout.strip()
    try:
        decision = json.loads(logs)
    except json.JSONDecodeError as error:
        lab.block(f"Synthetic integrity Job {name} did not emit one JSON decision: {error}")
    return {
        "job": name, "job_uid": job["metadata"]["uid"], "job_condition": terminal,
        "pod_uid": pod["metadata"]["uid"], "exit_code": terminated["exitCode"],
        "decision": decision,
    }


def _run_job(lab, name, mode, candidate, config=CONFIG):
    lab.create(_job(name, mode, candidate, config))
    return _observe_job(lab, name)


def run(lab):
    files = _fixture_data()
    config_map = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": CONFIG, "labels": {"saf-lab.example/control": "1005-015"}},
        "immutable": True, "data": files,
    }
    created = lab.create(config_map)
    observed_config = json.loads(lab.kubectl("get", "configmap", CONFIG, "-o", "json").stdout)
    lab.check("positive", "The case-owned fixture ConfigMap is persisted as immutable",
              observed_config.get("immutable") is True
              and observed_config.get("metadata", {}).get("uid") == created["metadata"]["uid"]
              and observed_config["data"] == files,
              {"immutable": observed_config.get("immutable"),
               "verified_api_readback": observed_config["data"] == files})

    attempted = lab.kubectl("patch", "configmap", CONFIG, "--type=merge",
                            "-p", json.dumps({"data": {"pre-incident.txt": "different inert text"}}),
                            allow_failure=True)
    after = json.loads(lab.kubectl("get", "configmap", CONFIG, "-o", "json").stdout)
    protected = attempted.returncode != 0 and "field is immutable" in attempted.stderr
    lab.check("green", "The API rejects an edit of the immutable fixture baseline",
              protected and after["data"] == files and after["metadata"]["uid"] == created["metadata"]["uid"],
              {"immutable_api_denial": protected, "fixture_bytes_preserved": after["data"] == files})

    no_approval = dict(files)
    approval = json.loads(no_approval["approval.json"])
    approval["decision"] = "pending"
    no_approval["approval.json"] = json.dumps(approval, sort_keys=True)
    alternate = CONFIG + "-pending"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": alternate},
                "immutable": True, "data": no_approval})
    pending = _run_job(lab, "saf-1005-015-pending-approval", "enforce", "reconstructed.txt", alternate)
    lab.check("green", "A byte-identical reconstruction remains blocked without approved metadata",
              pending["job_condition"] == "Failed" and pending["exit_code"] == 1
              and pending["decision"]["reason"] == "baseline_or_approval_invalid"
              and pending["decision"]["candidate_sha256"] == BASELINE_SHA256
              and pending["decision"]["approval_valid"] is False,
              {"job_condition": pending["job_condition"], "exit_code": pending["exit_code"],
               "decision": pending["decision"]})

    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    versions = sorted({node.get("status", {}).get("nodeInfo", {}).get("kubeletVersion")
                       for node in nodes})
    lab.check("positive", "The disposable cluster reports Kubernetes v1.36.1 nodes",
              bool(nodes) and versions == ["v1.36.1"], {"node_count": len(nodes), "kubelet_versions": versions})

    red = _run_job(lab, "saf-1005-015-bypass", "bypass", "changed.txt")
    green = _run_job(lab, "saf-1005-015-block-change", "enforce", "changed.txt")
    positive = _run_job(lab, "saf-1005-015-reconstruct", "enforce", "reconstructed.txt")

    evidence = {
        "notice": "Synthetic plain-text integrity exercise; no model, secret, feed, or external target.",
        "configmap_uid": observed_config["metadata"]["uid"],
        "preincident_sha256": BASELINE_SHA256,
        "fixture_sha256": {
            name: hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest()
            for name in ("pre-incident.txt", "reconstructed.txt", "changed.txt")
        },
        "node_kubelet_versions": versions,
        "jobs": {"red_bypass": red, "green_changed_candidate": green,
                 "positive_reconstruction": positive, "pending_approval": pending},
        "immutable_baseline_denial": attempted.stderr,
    }
    (lab.evidence / "integrity-observations.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lab.check("red", "The bypass comparator accepts the changed candidate without an integrity decision",
              red["job_condition"] == "Complete" and red["exit_code"] == 0
              and red["decision"].get("decision") == "accepted_without_integrity_check"
              and red["decision"].get("candidate_sha256") != BASELINE_SHA256,
              {"job_condition": red["job_condition"], "exit_code": red["exit_code"],
               "decision": red["decision"]})

    lab.check("green", "The enabled gate blocks a changed candidate despite matching synthetic approval metadata",
              green["job_condition"] == "Failed" and green["exit_code"] == 1
              and green["decision"].get("decision") == "blocked"
              and green["decision"].get("reason") == "candidate_digest_mismatch"
              and green["decision"].get("approval_valid") is True
              and green["decision"].get("candidate_sha256") != BASELINE_SHA256,
              {"job_condition": green["job_condition"], "exit_code": green["exit_code"],
               "decision": green["decision"]})

    lab.check("positive", "The enabled gate validates the approved byte-identical reconstruction",
              positive["job_condition"] == "Complete" and positive["exit_code"] == 0
              and positive["decision"].get("decision") == "reconstruction_validated"
              and positive["decision"].get("candidate_sha256") == BASELINE_SHA256
              and positive["decision"].get("baseline_sha256") == BASELINE_SHA256
              and positive["decision"].get("approval_id") == "approval-fixture-1005-015-001"
              and positive["decision"].get("approval_valid") is True,
              {"job_condition": positive["job_condition"], "exit_code": positive["exit_code"],
               "decision": positive["decision"]})
